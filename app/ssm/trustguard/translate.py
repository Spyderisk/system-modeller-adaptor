##///////////////////////////////////////////////////////////////////////
##
## TrustGuard -> Spyderisk translation
##
## >>> PLACEHOLDER — to be replaced with the real
## >>> TrustGuard -> Spyderisk ontology mapping once we have access to the
## >>> real TrustGuard JSON format and property semantics. <<<
##
##///////////////////////////////////////////////////////////////////////

from fastapi.logger import logger

# Spyderisk qualitative levels, lowest -> highest.
LEVELS = ["Very Low", "Low", "Medium", "High", "Very High"]
VALID_KINDS = ("trustworthiness", "impact")


def translate(tg_json: dict) -> list:
    """Normalise a TrustGuard asset json into SSM {kind, property, level} targets;

    PLACEHOLDER

    Returns a list of dicts:
        [{"kind": "trustworthiness"|"impact", "property": <str>, "level": <str>},
         {"kind": "control", "property": <control label>, "enabled": <bool>}, ...]
    """
    targets = []
    for attr in (tg_json or {}).get("attributes", []) or []:
        kind = attr.get("kind")
        prop = attr.get("property")
        level = attr.get("level")
        if kind not in VALID_KINDS or not prop or level not in LEVELS:
            logger.warning(f"[trustguard.translate] skipping invalid attribute: {attr}")
            continue
        targets.append({"kind": kind, "property": prop, "level": level})

    for ctl in (tg_json or {}).get("controls", []) or []:
        label = ctl.get("control")
        enabled = ctl.get("enabled")
        if not label or not isinstance(enabled, bool):
            logger.warning(f"[trustguard.translate] skipping invalid control: {ctl}")
            continue
        targets.append({"kind": "control", "property": label, "enabled": enabled})

    logger.info(f"[trustguard.translate]: {len(targets)} targets")
    return targets
