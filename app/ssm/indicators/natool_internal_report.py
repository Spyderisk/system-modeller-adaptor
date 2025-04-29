import json

#from app.models.state_report import AssetDesc, Trustworthiness, AdditionalProperty
#from app.models.state_report import StateItem, StateReportMessage
from app.models.state_report import *
from app.models.indicators.natool_model import NAToolReport

from app.crud.store_state_report import get_stored_state_report, get_all_reports
from app.crud.store_state_report import store_state_report, remove_state_report, remove_state_reports

from app.ssm.state_report_management.bg_process_state_reports import bg_process_state_reports

from fastapi.logger import logger

async def bg_process_natool_report(model_id: str, natool_report: NAToolReport, ssm, db_conn) -> int:
    """ Process NATool  tool report and convert it to an internal state report """

    logger.info("bg process natool report")

    try:
        # get aggregate_score e.g. 83.88

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
        logger.error("Exception when calling process NATool report: %s\n" % e)

    return 999
