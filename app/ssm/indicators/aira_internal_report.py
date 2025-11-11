import json

from fastapi.logger import logger

from app.models.state_report import AssetDesc, Trustworthiness, AdditionalProperty
from app.models.state_report import StateItem, StateReportMessage, OperatorEnum
from app.models.state_report import Expiry, ExpiryTypeEnum

from app.models.indicators.aira_model import AiraReport

from app.crud.store_state_report import store_state_report

from app.ssm.ssm_client import TWALevel


async def bg_process_aira_report(model_id: str, aira_report: AiraReport, ssm, db_conn) -> int:
    """
    Process Aira tool report and convert it to an internal state report.

    Returns:
        int: 0 on success, non-zero error code on failure.
    """

    SUCCESS, ERR_INVALID_LEVEL, ERR_NO_ASSET, ERR_NO_TWA, ERR_EXCEPTION = 0, 1, 2, 3, 999

    logger.info("bg process aira tool report")

    try:
        aggregate_score = aira_report.result.assessment.aggregate_score
        logger.info(f"Aira aggregate score: {aggregate_score}")

        proposed_tw_index = bin_index(aggregate_score)
        try:
            proposed_level = TWALevel(proposed_tw_index)
        except ValueError:
            logger.error(f"Invalid bin index {proposed_tw_index} for TWALevel")
            return ERR_INVALID_LEVEL

        logger.debug(f"Proposed TW level: {proposed_level.name.title()}")

        # find related asset
        identifiers = [{'key': 'host', 'value': 'ML'}]
        assets = ssm.get_ssm_assets_by_metadata(model_id, identifiers)
        if not assets:
            logger.warning(f"No asset found for model_id={model_id}")
            return ERR_NO_ASSET

        asset = assets[0]
        twa = get_twa(asset.id, "Extrinsic-U-TW", ssm, model_id)
        if not twa:
            logger.warning("Cannot find related TWA")
            return ERR_NO_TWA

        asset_desc = AssetDesc(properties=[AdditionalProperty(key="host", value="ML")])
        vuln_alert_twa_uri = twa.asserted_tw_level.uri[:87] + proposed_level.name.title()
        tw = Trustworthiness(trustworthinessAttribute=twa.uri, level=vuln_alert_twa_uri,
                             operator=OperatorEnum.LE)

        state_items = [StateItem(asset=asset_desc, trustworthiness=[tw], impacts=[], controls=[])]
        expiry = [Expiry(type=ExpiryTypeEnum.newest, label="aira")]

        state_report = StateReportMessage(expiry=expiry, state=state_items)
        logger.debug("Created state report:")
        logger.debug(json.dumps(state_report.dict(), indent=4, sort_keys=False))

        # TODO: persist state report
        state_id = await store_state_report(db_conn, model_id, state_report)
        logger.info(f"state_id: {state_id}")

        return state_id

    except Exception as e:
        logger.error(f"Exception when processing Aira report: {e}")
        #logger.debug(traceback.format_exc())
        return ERR_EXCEPTION


async def bg_process_aira_indicator(model_id: str, aira_report: AiraReport, ssm) -> bool:
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

    status = None

    try:
        # Extract aggregate_score
        aggregate_score = aira_report.result.assessment.aggregate_score
        logger.info(f"Aira aggregate score: {aggregate_score}")

        # Map score to bin / TWALevel
        proposed_tw_index = bin_index(aggregate_score)

        try:
            proposed_level = TWALevel(proposed_tw_index)
        except ValueError:
            logger.error(f"Invalid bin index {proposed_tw_index} for TWALevel")
            # status = internal error, invalid level?
            return False

        logger.debug(f"Proposed TW level: {proposed_level.name.title()}")

        # find related asset
        identifiers = [{'key': 'host', 'value': 'ML'}]
        assets = ssm.get_ssm_assets_by_metadata(model_id, identifiers)

        if not assets:
            logger.warning(f"No asset found for model_id={model_id}")
            # status = internal error, no asset found
            return False

        asset = assets[0]
        logger.debug(f"Identified model asset: {asset.label}")

        # get TWAs for this asset
        twas = ssm.get_asset_twas(asset.id, model_id)
        #TODO use AU VN and C instead of U (3 twas)
        target_twa_labels = ["Extrinsic-AU-TW", "Extrinsic-C-TW", "Extrinsic-VN-TW"]

        for twa in twas.values():
            if twa.attribute.label not in target_twa_labels:
                continue

            current_level = twa.asserted_tw_level
            logger.debug(f"Current TWA {twa.uri} level={current_level.label}")

            # update if new TWA level is lower
            if current_level.value > proposed_level.value:
                new_level = proposed_level.pascal_case
                logger.info(f"Updating TWA {twa.uri}: to {new_level}")
                updated = ssm.update_asset_twa(model_id, asset.id, twa.uri, new_level)
                if updated:
                    logger.info(f"Successfully updated TWA {twa.uri} to {new_level}")
                    status = True
                    continue
                logger.warning(f"Failed to update TWA {twa.uri} to {new_level}")
                status = False
                continue
            logger.info(f"Proposed TW level {proposed_level.name} is not lower than existing {current_level.label}")
            status = True
            continue

        #logger.warning(f"No TWA found with label {target_twa_label}")
        return status

    except Exception as e:
        logger.exception("Unexpected error while processing aira report: %s\n" % e)
        # status = internal error
    return False

def bin_index(value: float) -> int:
    if not (0 <= value <= 1):
        raise ValueError("Value must be between 0 and 100")
    return min(value // 0.2, 5)

def get_twa(asset_id, target_twa_label, ssm, model_id):

    # get TWAs for this asset
    twas = ssm.get_asset_twas(asset_id, model_id)

    for twa in twas.values():
        if twa.attribute.label != target_twa_label:
            continue
        return twa
