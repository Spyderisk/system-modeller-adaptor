from enum import Enum
import json

from fastapi.logger import logger

from app.models.state_report import AssetDesc, AdditionalProperty
from app.models.indicators.natool_model import NAToolReport

from app.crud.store_state_report import store_state_report

from app.core.config import NIST_API_KEY

from app.ssm.indicators.nvdcve import NVDCVE

from app.ssm.indicators.cve_utils import (
        build_state_report, fetch_cves,
        aggregate_twas, evaluate_twas_changes )


class ProcessStatus(Enum):
    SUCCESS = 0
    NO_ASSET = 1
    NO_CVE = 2
    NO_TWA_CHANGE = 3
    ERROR = 99


async def bg_process_natool_report(model_id: str, natool_report: NAToolReport, ssm, db_conn) -> list[int]:
    """Process NATool tool report and convert it to an internal state report."""
    logger.info("Processing NATool report...")

    state_ids: dict[int, str] = {}

    try:
        for entry_id, entry in natool_report.root.items():

            # each entry should be translated to an asset and list of CVEs

            state_ids[entry_id] = "start"
            logger.debug("ENTRY %s (IP=%s)", entry_id, entry.ip)

            basic_identifiers = get_basic_identifiers(entry)

            # Step 1: Collect CVEs, not much point to continue with no CVEs
            for detected_cve in entry.detected_cve:
                logger.info("checking %s", detected_cve)
                cve_names = [item.cve for item in detected_cve.cve]
                logger.debug(f" DETECTED CVES: {cve_names}")

                cve_names = [cve_item.cve for temp_i in (entry.detected_cve or []) for cve_item in (temp_i.cve or [])]
                if not cve_names:
                    logger.warning("No CVEs reported for entry %s", entry_id)
                    state_ids[entry_id] = ProcessStatus.NO_CVE.name
                    continue

                # identify asset from additional properties
                identifiers = basic_identifiers + get_detected_identifiers(detected_cve)

                # Query SSM
                assets = ssm.get_ssm_assets_by_metadata(model_id, identifiers)
                if not assets:
                    logger.warning("No asset found for entry %s with identifiers=%s", entry_id, identifiers)
                    state_ids[entry_id] = ProcessStatus.NO_ASSET.name
                    continue

                asset = assets[0]

                # Build asset description
                properties = [AdditionalProperty(**pair) for pair in identifiers]
                asset_desc = AssetDesc(properties=properties)

                # fetch CVE data from NVD
                nvd = NVDCVE(NIST_API_KEY)
                cves = fetch_cves(cve_names, nvd)
                if not cves:
                    logger.warning("No CVEs could be fetched for entry %s", entry_id)
                    state_ids[entry_id] = ProcessStatus.NO_CVE.name
                    continue

                # parse CVEs to TWA changes
                twas_changes = nvd.parse_cves(cves, asset.label, asset.id)
                if not twas_changes:
                    logger.warning("No applicable CVEs for asset %s in entry %s", asset.label, entry_id)
                    state_ids[entry_id] = ProcessStatus.NO_TWA_CHANGE.name
                    continue

                # compose state report
                state_report = build_state_report("natool", asset.id, asset_desc, twas_changes, ssm, model_id)
                logger.debug("Created state report for entry %s", entry_id)
                logger.debug(json.dumps(state_report.dict(), indent=4))

                # store state report
                state_id = await store_state_report(db_conn, model_id, state_report)
                logger.info("Stored state report with id %s for entry %s", state_id, entry_id)
                state_ids[entry_id] = state_id

        logger.debug(f"STATE IDs: {state_ids}")

    except Exception as e:
        logger.exception("Error while processing NATool report: %s", e)
        state_ids[-1] = ProcessStatus.ERROR.name

    return state_ids


async def bg_process_natool_indicator(model_id: str, natool_report: NAToolReport, ssm) -> int:
    logger.info("Starting NATool indicator process for model_id=%s", model_id)

    state_ids: dict[int, str] = {}

    try:
        for entry_id, entry in natool_report.root.items():

            # each entry should be translated to an asset and list of CVEs

            state_ids[entry_id] = "start"
            logger.debug("ENTRY %s (IP=%s)", entry_id, entry.ip)

            basic_identifiers = get_basic_identifiers(entry)

            # Step 1: Collect CVEs, not much point to continue with no CVEs
            for detected_cve in entry.detected_cve:
                logger.info("checking %s", detected_cve)
                cve_names = [item.cve for item in detected_cve.cve]
                logger.debug(f" DETECTED CVES: {cve_names}")

                if not cve_names:
                    logger.warning("No CVEs reported for entry %s", entry_id)
                    state_ids[entry_id] = ProcessStatus.NO_CVE.name
                    continue

                # Step 2: Find relevant asset, normally this should be the first step

                # identify asset from additional properties
                identifiers = basic_identifiers + get_detected_identifiers(detected_cve)

                # Query SSM
                assets = ssm.get_ssm_assets_by_metadata(model_id, identifiers)
                if not assets:
                    logger.warning("No asset found for entry %s with identifiers=%s", entry_id, identifiers)
                    state_ids[entry_id] = ProcessStatus.NO_ASSET.name
                    continue

                asset = assets[0]
                logger.info("Target asset: %s", asset.label)

                # fetch CVE data from NVD
                nvd = NVDCVE(NIST_API_KEY)
                cves = fetch_cves(cve_names, nvd)
                if not cves:
                    logger.warning("No CVEs could be fetched for entry %s", entry_id)
                    state_ids[entry_id] = ProcessStatus.NO_CVE.name
                    continue

                # parse CVEs to TWA changes
                twas_changes = nvd.parse_cves(cves, asset.label, asset.id)
                if not twas_changes:
                    logger.warning("No applicable CVEs for asset %s in entry %s", asset.label, entry_id)
                    state_ids[entry_id] = ProcessStatus.NO_CVE.name
                    continue

                logger.info("%d CVEs applicable for asset %s", len(cves), asset.label)

                # Step 4: Compare with current TWAs
                ref_twas = ssm.get_asset_twas(asset.id, model_id)
                ref_twas_aux_map = {twa.attribute.label: twa for twa in ref_twas.values()}

                dry_run_cache, stats = evaluate_twas_changes(twas_changes, ref_twas_aux_map)

                # Step 5: Aggregate and apply changes
                total_twa_changes = aggregate_twas(dry_run_cache)
                logger.info("Total TWA changes: %d for asset %s", len(total_twa_changes), asset.label)

                #TODO TWA changes are not recorded, need to define session, and rollback
                for twa_uri, twa_val in total_twa_changes.items():
                    logger.debug("Updating TWA %s -> %s", twa_uri[72:], twa_val)
                    #ssm.update_asset_twa(model_id, asset.id, twa_uri, twa_val, ref_twas[twa_uri])
                    ssm.update_asset_twa(model_id, asset.id, twa_uri, twa_val)

                #logger.info("Successfully applied %d TWA changes", len(total_twa_changes))
                state_ids[entry_id] = ProcessStatus.SUCCESS.name

            logger.debug(f"finished iteration {entry_id} {detected_cve}")

        logger.debug(f"STATE IDs: {state_ids}")

    except Exception:
        logger.exception("Fatal error processing NATool indicator")
        state_ids[-1] = ProcessStatus.ERROR.name

    return state_ids

def get_basic_identifiers(indicator):
    identifiers = []
    identifiers.append({"key": "ip", "value": indicator.ip})

    # Add TCP/UDP ports if present
    #if indicator.open_tcp_ports:
    #    identifiers.extend([{"key": "TCP", "value": p} for p in indicator.open_tcp_ports])
    #if indicator.open_udp_ports:
    #    identifiers.extend([{"key": "UDP", "value": p} for p in indicator.open_udp_ports])

    return identifiers

def get_detected_identifiers(detected_cve):
    """ dectcted_cve is a list, each element represents a potential service,
    ony one service at a time should be considered not all of them
    """
    identifiers = []

    # Add detected service metadata if available
    #if detected_cve.product:
    #    identifiers.append({"key": "product", "value": detected_cve.product})
    if detected_cve.name:
        identifiers.append({"key": "name", "value": detected_cve.name})

    return identifiers

def get_asset_identifiers(indicator):
    """Build identifiers from indicator and query SSM for the asset.
    Extract product value if available, otherwise get the IP value
    """
    identifiers = []

    # Add detected service metadata if available
    for detected_cve in (indicator.detected_cve or []):
        #if detected_cve.product:
        #    identifiers.append({"key": "product", "value": detected_cve.product})
            # return identifiers
        if detected_cve.name:
            identifiers.append({"key": "name", "value": detected_cve.name})

    if not identifiers:
        identifiers.append({"key": "ip", "value": indicator.ip})

    logger.debug("Asset identifiers looking for product or ip: %s", identifiers)

    # TODO TEMPORARY: override for testing only
    #identifiers = [{"key": "host", "value": "ML"}, {"key": "port", "value": "80"}]

    return identifiers


def get_asset_identifiers_all(indicator):
    """Build identifiers from indicator and query SSM for the asset."""
    identifiers = []
    identifiers.append({"key": "ip", "value": indicator.ip})

    # Add TCP/UDP ports if present
    if indicator.open_tcp_ports:
        identifiers.extend([{"key": "TCP", "value": p} for p in indicator.open_tcp_ports])
    if indicator.open_udp_ports:
        identifiers.extend([{"key": "UDP", "value": p} for p in indicator.open_udp_ports])

    # Add detected service metadata if available
    for detected_cve in (indicator.detected_cve or []):
        if detected_cve.name:
            identifiers.append({"key": "name", "value": detected_cve.name})
        if detected_cve.product:
            identifiers.append({"key": "product", "value": detected_cve.product})

    logger.debug("Asset identifiers: %s", identifiers)

    # TODO TEMPORARY: override for testing only
    #identifiers = [{"key": "host", "value": "ML"}, {"key": "port", "value": "80"}]

    return identifiers
