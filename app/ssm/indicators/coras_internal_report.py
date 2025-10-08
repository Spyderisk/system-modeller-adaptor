import re

from typing import List, Tuple
import hashlib

#from app.models.state_report import AssetDesc, Trustworthiness, AdditionalProperty
#from app.models.state_report import StateItem, StateReportMessage
from app.models.state_report import *
from app.models.indicators.coras_model import CorasReport

from app.crud.store_state_report import get_stored_state_report, get_all_reports
from app.crud.store_state_report import store_state_report, remove_state_report, remove_state_reports

from app.ssm.state_report_management.bg_process_state_reports import bg_process_state_reports
from app.ssm.ssm_client import TWALevel, LikelihoodLevel

from app.ssm.protego.bg_alert_mappings import AlertMappings

from app.ssm.indicators.nvdcve import NVDCVE
from app.core.config import NIST_API_KEY

from fastapi.logger import logger

from app.models.ssm.twa import TWA, TWAChange
from app.ssm.indicators.cve_utils import DryEntry

from dataclasses import dataclass, field
from typing import List, Tuple

CWEC_FILE = "app/static/mappings/cwec.csv"

@dataclass
class DryEntryX:
    risk: str = None
    cves: List[str]= field(default_factory=list)
    twa_pairs: List[Tuple[str, str]] = field(default_factory=list)

class ProcessStatus(Enum):
    SUCCESS = 0
    NO_ASSET = 1
    NO_CVE = 2
    NO_TWA_CHANGE = 3
    ERROR = 99

#async def bg_process_coras_report(model_id: str, coras_report: CorasReport, ssm, db_conn) -> int:
async def bg_process_coras_report(model_id: str, ssm, db_conn) -> int:
    """ Process Coras tool report and convert it to an internal state report """

    logger.info("bg process coras report")

    try:

       return 9876

    except Exception as e:
        logger.error("Exception when calling process Coras report: %s\n" % e)
        return ProcessStatus.ERROR.value


def parse_cwe_twa(cwe_str):
    if not cwe_str:
        logger.warning("Empty CWE string passed to parse_cwedict")
        return [], None

    # Handle case where it's a list or tuple
    if isinstance(cwe_str, (list, tuple)):
        expr = cwe_str[0].strip()
    else:
        expr = cwe_str.strip()

    if expr == '??':
        return [], None

    # Detect OR / list logic
    if re.search(r'\bor\b', expr, flags=re.IGNORECASE):
        items = re.split(r'\bor\b', expr, flags=re.IGNORECASE)
        logic = 'OR'
    else:
        items = re.split(r'[,\s]+', expr)
        logic = 'LIST'

    items = [x.strip() for x in items if x.strip()]
    return items, logic


def parse_cwe_row(node, cwe_row):
    if not cwe_row:
        logger.warning(f"No CWE data for node {node}")
        return None, None

    twa_new_level = cwe_row.get('TWA New Level')
    if twa_new_level == '??':
        #twa_new_level = TWALevel[node.indicator.likelihood.upper()].flipped.name
        twa_new_level = LikelihoodLevel[node.indicator.likelihood.upper()].toTWALevel.name
        logger.debug(f"Unknown TWA New Level, using node likelihood flipped: {twa_new_level}")

    try:
        proposed_level = TWALevel[twa_new_level.upper()]
    except KeyError:
        logger.error(f"Invalid TWA level '{twa_new_level}' in CWE row {cwe_row}")
        return None, None

    twas_str = cwe_row.get('TWA')
    target_twas, logic = parse_cwe_twa(twas_str)

    if not logic:
        logger.warning(f"Skipping deprecated or invalid CWE: {cwe_row}")
        return None, None

    if logic == 'OR':
        logger.debug("CWE has OR condition, simplifying selection")
        if TWALevel[node.indicator.importance.upper()] > TWALevel.MEDIUM:
            target_twas = [target_twas[0]]
        else:
            target_twas = [target_twas[-1]]

    if not node.indicator.authentication:
        target_twas.append("Extrinsic-AU")

    if node.indicator.accessVector:
        target_twas.append("Extrinsic-VN")

    for twa in target_twas:
        logger.debug(f"Target TWA: {twa} -> proposed level {proposed_level.name}")

    return target_twas, proposed_level

def parse_in_type(node):

    target_twas = ["Astuteness"]

    indicator_likelihood = node.indicator.likelihood.upper()
    proposed_level = LikelihoodLevel[indicator_likelihood].toTWALevel

    logger.debug(f"IN type 10, using node likelihood {indicator_likelihood} converted to: {proposed_level.name}")

    logger.debug(f"Target TWA: {target_twas[0]} -> proposed level {proposed_level.name}")

    return target_twas, proposed_level


async def bg_process_coras_indicator(model_id: str, coras_report: CorasReport, ssm, db_conn) -> int:
    logger.info(f"Starting CORAS indicator process for model_id={model_id}")

    am = AlertMappings()
    cwe_dict = am.readInCWEs(CWEC_FILE)
    status = ProcessStatus.NO_ASSET.value

    try:
        for node in coras_report.nodes:
            if not (node.indicator.isindicator and node.indicator.indicator_type in ["CWE", "IN"]):
                continue

            logger.debug(f"Processing node: {node}")
            identifiers = [{"key": "coras_identifier", "value": node.indicator.ssm_asset_identifier}]
            assets = ssm.get_ssm_assets_by_metadata(model_id, identifiers)

            if not assets:
                logger.warning(f"No asset found for node {node}")
                continue

            asset = assets[0]
            logger.debug(f"Matched asset: {asset.label}")

            if node.indicator.indicator_type == "IN" and node.indicator.indicator_value == '10':
                logger.info("dealing with IN type node")
                target_twas, proposed_level = parse_in_type(node)
            elif node.indicator.indicator_type == "CWE":
                logger.info("dealing with CWE type node")
                cwe_num = node.indicator.indicator_value
                cwe_row = cwe_dict.get(cwe_num)
                target_twas, proposed_level = parse_cwe_row(node, cwe_row)
            else:
                logger.warning(f"unknown type of indicator node: {node}")
                continue

            if not target_twas or not proposed_level:
                logger.debug(f"Skipping node {node}, invalid mapping")
                continue

            twas = ssm.get_asset_twas(asset.id, model_id)
            for twa in twas.values():
                #label = twa.attribute.label[:-3] if twa.attribute.label.endswith("-TW") else twa.attribute.label
                label = twa.attribute.label.removesuffix("-TW")
                if label not in target_twas:
                    continue

                logger.debug(f"identified TWA candidate: {twa.attribute.label}")

                current_level = twa.asserted_tw_level
                if current_level.value > proposed_level.value:
                    new_level = proposed_level.pascal_case
                    logger.info(f"Updating TWA {twa.uri}: to {new_level}")
                    updated = ssm.update_asset_twa(model_id, asset.id, twa.uri, new_level)

                    if updated:
                        logger.info(f"Updated TWA {twa.uri} to {new_level}")
                        status = True
                    else:
                        logger.warning(f"Failed to update TWA {twa.uri}")
                        status = ProcessStatus.ERROR.value
                else:
                    logger.debug(
                        f"No update: proposed={proposed_level.name}, current={current_level.label.upper()}"
                    )

        logger.debug("Finished processing all CORAS nodes")
        return status

    except Exception:
        logger.exception("Fatal error in CORAS indicator processing")
        return ProcessStatus.ERROR.value

