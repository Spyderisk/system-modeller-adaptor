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
        [{"kind": "trustworthiness"|"impact", "property": <str>, "level": <str>}, ...]
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

    logger.info(f"[trustguard.translate]: {len(targets)} target attributes")
    return targets
