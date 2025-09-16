import json

#from app.models.state_report import AssetDesc, Trustworthiness, AdditionalProperty
#from app.models.state_report import StateItem, StateReportMessage
from app.models.state_report import *
from app.models.indicators.aira_model import AiraReport

from app.crud.store_state_report import get_stored_state_report, get_all_reports
from app.crud.store_state_report import store_state_report, remove_state_report, remove_state_reports

from app.ssm.state_report_management.bg_process_state_reports import bg_process_state_reports
from app.ssm.ssm_client import TWALevel

from fastapi.logger import logger

async def bg_process_aira_report(model_id: str, aira_report: AiraReport, ssm, db_conn) -> int:
    """ Process Aira tool report and convert it to an internal state report """

    logger.info("bg process aira tool report")

    try:
        # get aggregate_score e.g. 83.88
        aggregate_score = aira_report.result.assessment.aggregate_score
        logger.info(f"Aira aggregate score: {aggregate_score}")

        # find model relevant asset
        properties = []
        properties.append(AdditionalProperty(key="host", value='ML'))

        assetDesc = AssetDesc(properties=properties)

        # find update TWA

        tw_items = []

        # Build TW attribute URI

        stem = f"http://it-innovation.soton.ac.uk/ontologies/" \
                f"trustworthiness/domain#TrustworthinessLevel"

        domain_prefix = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#"

        twa_level = "TrustworthinessLevelMedium"
        #vuln_alert_twa_uri = stem + twa_level
        vuln_alert_twa_uri = domain_prefix + twa_level

        twa = domain_prefix + twa_level  + "-TW"

        # Create Trustworthiness object using TW attribute and level
        tw = Trustworthiness(trustworthinessAttribute=twa, level=vuln_alert_twa_uri, operator=OperatorEnum.EQ)

        # Add to state item TW list
        tw_items.append(tw)

        # compose and submit internal state report
        state_items = [StateItem(asset=assetDesc, trustworthiness=tw_items, impacts=[], controls=[])]

        # Set expiry to "newest" and label as "openvas"
        expiry = [Expiry(type=ExpiryTypeEnum.newest, label="openvas")]

        # Create state report
        state_report = StateReportMessage(expiry=expiry, state=state_items)
        logger.info(f"Created state report:")
        logger.info(json.dumps(state_report.dict(), indent=4, sort_keys=False))

        # Store the state report
        #state_id = await store_state_report(db_conn, model_id, state_report)
        #logger.info(f"state_id: {state_id}")

    except Exception as e:
        logger.error("Exception when calling process aira report: %s\n" % e)

    return 999

async def bg_process_aira_indicator(model_id: str, aira_report: AiraReport, ssm, db_conn) -> bool:
    """
    Process Aira tool report and convert it to TWA changes in the model

    Args:
        model_id (str): Identifier of the model.
        aira_report (AiraReport): Parsed Aira tool report.
        ssm: SSM client.
        db_conn: Database connection (unused for now).

    Returns:
        bool: True if TWA update succeeded, False otherwise.
    """

    logger.info("bg apply aira tool report indicator...")

    try:
        # Extract aggregate_score
        aggregate_score = aira_report.result.assessment.aggregate_score
        logger.info(f"Aira aggregate score: {aggregate_score}")

        # Map score to bin / TWALevel
        proposed_tw_index = _bin_index(aggregate_score)
        proposed_tw_index = _bin_index(45)

        try:
            proposed_level = TWALevel(proposed_tw_index)
        except ValueError:
            logger.error(f"Invalid bin index {proposed_tw_index} for TWALevel")
            return False

        logger.debug(f"Proposed TW level: {proposed_level.name.title()}")

        # find related asset
        identifiers = {'host': 'ML'}
        assets = ssm.get_ssm_asset(model_id, **identifiers)

        if not assets:
            logger.warning(f"No asset found for model_id={model_id}")
            return False

        asset = assets[0]

        # get TWAs for this asset
        twas = ssm.get_asset_twas(asset.id, model_id)
        target_twa_label = "Extrinsic-U-TW"

        for twa in twas.values():
            if twa.attribute.label != target_twa_label:
                continue

            current_level = twa.asserted_tw_level
            logger.debug(f"Current TWA {twa.uri} level={current_level.label}")

            # update if new TWA level is lower
            if current_level.value > proposed_level.value:
                new_level = proposed_level.name.title()
                updated = ssm.update_twas_single(model_id, asset.id, twa.uri, new_level)
                if updated:
                    logger.info(f"Successfully updated TWA {twa.uri} to {new_level}")
                    return True
                else:
                    logger.warning(f"Failed to update TWA {twa.uri} to {new_level}")
                    return False
            else:
                logger.info(f"Proposed TW level {proposed_level.name} is not lower than existing {current_level.label}")
                return False

        logger.warning(f"No TWA found with label {target_twa_label}")
        return False

    except Exception as e:
        logger.exception("Unexpected error while processing aira report: %s\n" % e)
    return False

def _bin_index(value: float) -> int:
    if not (0 <= value <= 100):
        raise ValueError("Value must be between 0 and 100")
    return min(value // 20, 5)

