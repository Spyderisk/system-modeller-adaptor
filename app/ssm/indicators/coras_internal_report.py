import json

from collections import defaultdict
from typing import Dict, List, Tuple
import hashlib

#from app.models.state_report import AssetDesc, Trustworthiness, AdditionalProperty
#from app.models.state_report import StateItem, StateReportMessage
from app.models.state_report import *
from app.models.indicators.natool_model import NAToolReport

from app.crud.store_state_report import get_stored_state_report, get_all_reports
from app.crud.store_state_report import store_state_report, remove_state_report, remove_state_reports

from app.ssm.state_report_management.bg_process_state_reports import bg_process_state_reports
from app.ssm.ssm_client import TWALevel

from app.ssm.indicators.nvdcve import NVDCVE
from app.core.config import NIST_API_KEY

from fastapi.logger import logger

from app.models.ssm.twa import TWA, TWAChange

from dataclasses import dataclass, field
from typing import List, Tuple

@dataclass
class DryEntry:
    risk: str = None
    cves: List[str]= field(default_factory=list)
    twa_pairs: List[Tuple[str, str]] = field(default_factory=list)

class ProcessStatus(Enum):
    SUCCESS = 0
    NO_ASSET = 1
    NO_CVE = 2
    NO_TWA_CHANGE = 3
    ERROR = 99

#async def bg_process_coras_report(model_id: str, natool_report: NAToolReport, ssm, db_conn) -> int:
async def bg_process_coras_report(model_id: str, ssm, db_conn) -> int:
    """ Process Coras tool report and convert it to an internal state report """

    logger.info("bg process coras report")

    #TODO natool will provide a list of CVEs and a target asset, from the analysis
    # of CVEs we will endup with a list of TWA changes to be added in the state
    # report.

    try:
        # step1 find the affected asset(s)

        # find model relevant asset
        properties = []
        properties.append(AdditionalProperty(key="host", value='ML'))

        asset_desc = AssetDesc(properties=properties)

        # Step 1: Find relevant asset
        asset = _get_asset_for_model(model_id, ssm)
        if not asset:
            return ProcessStatus.NO_ASSET.value

        # step2 search NIST for CVEs and create a list of cves
        nvd = NVDCVE(NIST_API_KEY)
        cve_names = ["CVE-2020-14385", "CVE-2021-47547"]

        # Step 2: Collect CVEs (hardcoded for now, should come from NATool)
        cves = _fetch_cves(cve_names, nvd)
        if not cves:
            logger.warning("No CVEs could be fetched for model_id=%s", model_id)
            return ProcessStatus.NO_CVE.value

        # Step 3: Parse CVEs into TWA changes
        nvd.records = []
        twas_changes = nvd.parse_cves(cves, asset.label, asset.id)

        logger.debug(f"TWA_CHANGES: {twas_changes}")

        if not twas_changes:
            logger.warning("No applicable CVEs for {asset.label} found after parsing")
            return ProcessStatus.NO_TWA_CHANGE.value

        logger.info("%d CVEs applicable for asset %s", len(cves), asset.label)

        ref_twas = ssm.get_asset_twas(asset.id, model_id)
        ref_twas_aux_map = {twa.attribute.label: twa for twa in ref_twas.values()}

        dry_run_cache, stats =  evaluate_twas_changes(twas_changes, ref_twas_aux_map)

        logger.info("Dry run stats: %s", stats)

        domain_level_prefix = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#TrustworthinessLevel"
        tw_list = [
            Trustworthiness(
                trustworthinessAttribute=twa[0],
                level=f"{domain_level_prefix}{twa[1]}",
                operator=OperatorEnum.LE
            )
            for run in dry_run_cache.values()
            for twa in run.twa_pairs
        ]

        state_items = [StateItem(asset=asset_desc, trustworthiness=tw_list, impacts=[], controls=[])]
        expiry = [Expiry(type=ExpiryTypeEnum.newest, label="coras")]

        state_report = StateReportMessage(expiry=expiry, state=state_items)
        logger.debug("Created state report:")
        logger.debug(json.dumps(state_report.dict(), indent=4, sort_keys=False))

        # Store the state report
        state_id = await store_state_report(db_conn, model_id, state_report)
        logger.info(f"state_id: {state_id}")
        return state_id

    except Exception as e:
        logger.error("Exception when calling process Coras report: %s\n" % e)
        return ProcessStatus.ERROR.value


def _fetch_cves(cve_names: list[str], nvd) -> list[dict]:
    cves = []
    for cve_name in cve_names:
        try:
            data = nvd.get_nvd_data(cve_name)
            if not data:
                logger.warning(f"No data returned for {cve_name}")
                continue
            cves.append(data)
        except Exception as e:
            logger.exception(f"Error fetching CVE {cve_name}: {e}")
    return cves

def _get_asset_for_model(model_id: str, ssm):
    identifiers = {"host": "ML"} # TODO: make dynamic
    assets = ssm.get_ssm_asset(model_id, **identifiers)
    if not assets:
        logger.warning("No asset found for model_id=%s", model_id)
        return None
    return assets[0]

def _aggregate_twas(dry_run_cache):
    total_twa_changes = {}
    for run in dry_run_cache.values():
        for twa_key, twa_value in run.twa_pairs:
            existing = total_twa_changes.get(twa_key)
            if (
                existing is None
                or TWALevel[twa_value.upper()] < TWALevel[existing.upper()]
            ):
                total_twa_changes[twa_key] = twa_value
    return total_twa_changes

#async def bg_process_coras_indicator(model_id: str, natool_report: NAToolReport, ssm, db_conn) -> int:
async def bg_process_coras_indicator(model_id: str, ssm, db_conn) -> int:
    logger.info("Starting coras indicator process for model_id=%s", model_id)

    try:
        # Step 1: Find relevant asset
        asset = _get_asset_for_model(model_id, ssm)
        if not asset:
            return ProcessStatus.NO_ASSET.value

        # Step 2: Collect CVEs (hardcoded for now, should come from NATool)
        nvd = NVDCVE(NIST_API_KEY)
        cve_names = ["CVE-2020-14385", "CVE-2021-47547"]

        cves = _fetch_cves(cve_names, nvd)
        if not cves:
            logger.warning("No CVEs could be fetched for model_id=%s", model_id)
            return ProcessStatus.NO_CVE.value

        # Step 3: Parse CVEs into TWA changes
        nvd.records = [] # reset state
        twas_changes = nvd.parse_cves(cves, asset.label, asset.id)

        if not twas_changes:
            logger.warning("No applicable CVEs for %s found after parsing", asset.label)
            return ProcessStatus.NO_TWA_CHANGE.value

        logger.info("%d CVEs applicable for asset %s", len(cves), asset.label)

        # Step 4: Compare with current TWAs
        ref_twas = ssm.get_asset_twas(asset.id, model_id)
        ref_twas_aux_map = {twa.attribute.label: twa for twa in ref_twas.values()}

        dry_run_cache, stats = evaluate_twas_changes(twas_changes, ref_twas_aux_map)
        logger.info("Dry run stats: %s", stats)

        # Step 5: Aggregate and apply changes
        total_twa_changes = _aggregate_twas(dry_run_cache)
        logger.info("Total TWA changes: %d", len(total_twa_changes))

        for twa_uri, twa_val in total_twa_changes.items():
            logger.debug("Updating TWA %s -> %s", twa_uri[76:], twa_val)
            #ssm.update_twas_single(model_id, asset.id, twa_uri, twa_val)

        logger.info("Successfully applied %d TWA changes", len(total_twa_changes))
        return ProcessStatus.SUCCESS.value

    except Exception:
        logger.exception("Fatal error processing coras indicator")
        return ProcessStatus.ERROR.value

#TODO move this method to a separate file?
def evaluate_twas_changes(
    twas_changes: List["TWAChange"],
    ref_twas_aux_map: Dict[str, "TWA"]
    ) -> Tuple[Dict[str, DryEntry], Dict[str, int]]:
    """
    Evaluate proposed TWA changes against existing asset TWAs.

    Returns:
        dry_run_cache: mapping of unique signatures to DryEntry results
        dry_run_stats: statistics about duplicates, potential changes, etc.
    """
    logger.info("Evaluate TWA changes")

    # deterministic hashing function
    def stable_hash(obj: object) -> str:
        return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()

    dry_run_cache: Dict[str, DryEntry] = {}
    dry_run_stats: Dict[str, int] = defaultdict(int)
    secondary_signature: Dict[str, str] = {}

    for twa_change in twas_changes:
        twa_signature = stable_hash(twa_change.twas)

        logger.debug(
            f"evaluating CVE: {twa_change.cve_name}, signature: {twa_signature}"
        )

        # Case 1: Exact duplicate
        if twa_signature in dry_run_cache:
            logger.info(
                f"{twa_change.cve_name} is redundant, already covered by "
                f"{dry_run_cache[twa_signature].cves}"
            )
            dry_run_cache[twa_signature].cves.append(twa_change.cve_name)
            dry_run_stats["duplicate"] += 1
            continue

        # create new entry
        dry_run_entry = DryEntry(cves=[twa_change.cve_name])

        # Filter TWAs with a truthy (non-null) value
        valid_twas = {k: v for k, v in twa_change.twas.items() if v}
        if not valid_twas:
            dry_run_stats["irrelevant"] += 1
            logger.warning(
                f"{twa_change.cve_name}: no proposed TWAs found, skipping..."
            )
            continue

        logger.info("Matching asset TWAs with suggested vulnerability changes")

        for twa_key, tw_new_level in valid_twas.items():
            twa = ref_twas_aux_map.get(twa_key)
            if not twa:
                logger.info(
                    f"Skipping suggested {twa_key}: not found in asset TWA list"
                )
                continue

            try:
                if TWALevel[tw_new_level.upper()] > TWALevel[twa.asserted_tw_level.label.upper()]:
                    dry_run_entry.twa_pairs.append((twa.uri, tw_new_level))
                    logger.info(
                        f"Applicable: {twa.attribute.label} {twa.asserted_tw_level.label} --> {tw_new_level}"
                    )
                else:
                    logger.debug(
                        f"No downgrade: keeping {twa.attribute.label} at {twa.asserted_tw_level.label}"
                    )
            except KeyError:
                logger.error(
                    f"Invalid TWA level '{tw_new_level}' for {twa_key}, skipping."
                )

        # Case 2: Secondary redundancy check
        if dry_run_entry.twa_pairs:
            reduced_signature = stable_hash(dry_run_entry.twa_pairs)
            if reduced_signature in secondary_signature:
                first_key = secondary_signature[reduced_signature]
                dry_run_cache[first_key].cves.append(f"{twa_change.cve_name}*")
                dry_run_stats["contained_duplicate"] += 1
                logger.info(f"Secondary duplicate: {twa_change.cve_name}* skipped.")
            else:
                secondary_signature[reduced_signature] = twa_signature
                dry_run_cache[twa_signature] = dry_run_entry
                dry_run_stats["potential"] += 1
        else:
            dry_run_stats["irrelevant"] += 1
            logger.debug(f"{twa_change.cve_name} introduces no TWA changes.")

    stats_msg = "\n".join(f" - {k}: {v}" for k, v in dry_run_stats.items())
    logger.debug(f"TWAs changes evaluation complete:\n{stats_msg}")

    return dry_run_cache, dry_run_stats

