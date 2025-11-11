from dataclasses import dataclass, field
from typing import Dict, List, Tuple
from collections import defaultdict
import hashlib
import json

from fastapi.logger import logger

from app.models.state_report import Trustworthiness
from app.models.ssm.twa import TWA, TWAChange
from app.models.state_report import StateItem, StateReportMessage, OperatorEnum
from app.models.state_report import Expiry, ExpiryTypeEnum

from app.ssm.ssm_client import TWALevel

@dataclass
class DryEntry:
    risk: str = None
    cves: List[str]= field(default_factory=list)
    twa_pairs: List[Tuple[str, str]] = field(default_factory=list)


def build_state_report(label, asset_id, asset_desc, twas_changes, ssm, model_id) -> StateReportMessage:
    ref_twas = ssm.get_asset_twas(asset_id, model_id)
    ref_map = {twa.attribute.label: twa for twa in ref_twas.values()}

    dry_run_cache, stats = evaluate_twas_changes(twas_changes, ref_map)
    logger.info("Dry run stats: %s", stats)

    domain_prefix = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#TrustworthinessLevel"
    tw_list = [
        Trustworthiness(
            trustworthinessAttribute=twa[0],
            level=f"{domain_prefix}{twa[1]}",
            operator=OperatorEnum.LE,
        )
        for run in dry_run_cache.values()
        for twa in run.twa_pairs
    ]

    state_items = [StateItem(asset=asset_desc, trustworthiness=tw_list, impacts=[], controls=[])]
    expiry = [Expiry(type=ExpiryTypeEnum.newest, label=label)]

    return StateReportMessage(expiry=expiry, state=state_items)


def fetch_cves(cve_names: list[str], nvd) -> list[dict]:
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
            continue
    return cves


def aggregate_twas(dry_run_cache):
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
    logger.info("Evaluate proposed TWA changes")

    # deterministic hashing function on TWA levels, e.g.
    #{'Extrinsic-A-TW': None, 'Extrinsic-AU-TW': 'Low', ...}
    def stable_hash(obj: object) -> str:
        return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()

    dry_run_cache: Dict[str, DryEntry] = {}
    dry_run_stats: Dict[str, int] = defaultdict(int)
    secondary_signature: Dict[str, str] = {}

    for twa_change in twas_changes:
        twa_signature = stable_hash(twa_change.twas)

        #logger.debug(f"evaluating CVE: {twa_change.cve_name}, signature: {twa_signature}")

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

        #logger.info("Matching asset TWAs with suggested vulnerability changes")

        for twa_key, tw_new_level in valid_twas.items():
            twa = ref_twas_aux_map.get(twa_key)
            if not twa:
                logger.info(
                    f"Skipping suggested {twa_key}: not found in asset TWA list"
                )
                continue

            try:
                if TWALevel[tw_new_level.upper()] < TWALevel[twa.asserted_tw_level.label.upper()]:
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
    #logger.debug(f"TWAs changes evaluation complete:\n{stats_msg}")

    return dry_run_cache, dry_run_stats

