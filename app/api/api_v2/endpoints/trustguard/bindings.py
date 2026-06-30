##///////////////////////////////////////////////////////////////////////
##
## TrustGuard external-binding endpoints
##
## Provides the adaptor side of the generic "external asset binding" feature:
##   POST   /v2/trustguard/models/{model_webkey}/bind        -> fetch+translate+apply
##
## On bind: call the TrustGuard client -> translate -> apply impacts/TWAs via
## ssmclientlib. The binding metadata is recorded by the SSM widget, not here:
## the adaptor is metadata-agnostic and only applies levels.
##
##///////////////////////////////////////////////////////////////////////

import requests
from fastapi import APIRouter, Path, HTTPException, status, Request
from pydantic import BaseModel
from fastapi.logger import logger

from app.ssm.ssm_client import SSMClient
from app.clients.trustguard_client import TrustGuardClient, TrustGuardError
from app.ssm.trustguard.translate import translate
router = APIRouter(prefix="/trustguard", tags=["TrustGuard"])


class BindRequest(BaseModel):
    asset_id: str
    external_id: str


# ---------------------------------------------------------------------------
# TEMPORARY: ssmclient extended with bulk-endpoint methods.
# Remove this whole block and revert _authed_ssm to a plain SSMClient() once
# ssmclientlib is regenerated, then call the generated ssm.api_asset.<stub> instead.
# ---------------------------------------------------------------------------
class _SSMClientWithBulk(SSMClient):
    """SSMClient extended with the new bulk TWAS/impact endpoints"""

    def __init__(self, *args, cookie=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._fwd_cookie = cookie

    def _bulk_headers(self):
        return {"Cookie": self._fwd_cookie} if self._fwd_cookie else {}

    def update_twas_bulk(self, model_id, asset_id, twas_payload):
        r = requests.put(
            f"{self.ssm_host}/models/{model_id}/assets/{asset_id}/twas/bulk",
            json=twas_payload, headers=self._bulk_headers(), timeout=30)
        r.raise_for_status()
        return r

    def update_impact_bulk(self, model_id, ms_payload):
        r = requests.put(
            f"{self.ssm_host}/models/{model_id}/misbehaviours/impact/bulk",
            json=ms_payload, headers=self._bulk_headers(), timeout=30)
        r.raise_for_status()
        return r
# --------------------------- end TEMPORARY block ---------------------------


def _authed_ssm(http_request: Request) -> SSMClient:
    """Build a fresh SSMClient whose calls carry the user's forwarded SSM session cookie"""
    cookie = http_request.headers.get("cookie")
    ssm = _SSMClientWithBulk(cookie=cookie)
    if cookie:
        # All api_* share one ApiClient, so this header applies to every call.
        ssm.api_asset.api_client.set_default_header("Cookie", cookie)
    return ssm


# TODO: don't rely on URI structure, query ssm the URIs for the levels.
def _set_level_uri(level_obj, level_label):
    """Rewrite a Level object's uri to point at <base>#<TypePrefix><LevelLabel>,
    keeping the same level type prefix (TrustworthinessLevel / ImpactLevel) and
    base namespace already present on the object. Returns the new uri or None."""
    if level_obj is None or not getattr(level_obj, "uri", None):
        return None
    old_uri = level_obj.uri
    base, _, frag = old_uri.partition("#")
    # frag looks like "TrustworthinessLevelMedium" or "ImpactLevelHigh";
    # strip the trailing level label to recover the type prefix.
    for prefix in ("TrustworthinessLevel", "ImpactLevel"):
        if frag.startswith(prefix):
            # SSM level URIs end with the label without spaces: 'Very High' -> 'VeryHigh'.
            new_uri = f"{base}#{prefix}{level_label.replace(' ', '')}"
            level_obj.uri = new_uri
            return new_uri
    return None


@router.post("/models/{model_webkey}/bind")
async def bind_asset(
    body: BindRequest,
    http_request: Request,
    model_webkey: str = Path(..., title="Model id/webkey"),
):
    """Fetch the TrustGuard properties for `external_id`, translate them
    and apply the result to the SSM asset `asset_id` as impact
    levels (on its misbehaviour sets) and trustworthiness levels (on its TWAs).
    """
    request = body
    ssm = _authed_ssm(http_request)

    # 1. Fetch from TrustGuard.
    try:
        tg_json = TrustGuardClient().get_asset(request.external_id)
    except TrustGuardError as e:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(e))

    # 2. Translate: list of {kind, property, level} targets.
    targets = translate(tg_json)
    tw_targets = {t["property"].lower(): t["level"] for t in targets if t["kind"] == "trustworthiness"}
    imp_targets = {t["property"].lower(): t["level"] for t in targets if t["kind"] == "impact"}

    summary = {
        "asset_id": request.asset_id,
        "external_id": request.external_id,
        "translated": targets,
        "applied": {"twas": [], "impacts": [], "unmatched": [], "errors": []},
    }

    # 3a. Match trustworthiness targets to the asset's TWAs (by attribute label)
    twa_payload = []
    if tw_targets:
        try:
            twas = ssm.api_asset.get_asset_twas(model_webkey, request.asset_id)
            for twa in (twas or {}).values():
                attr_label = (getattr(twa.attribute, "label", None) or "").lower()
                level = tw_targets.get(attr_label)
                if not level or _set_level_uri(twa.asserted_tw_level, level) is None:
                    continue
                twa.tw_level_asserted = True
                twa_payload.append(twa.to_dict())
                summary["applied"]["twas"].append({"twa": twa.attribute.label, "level": level})
        except Exception as e:
            summary["applied"]["errors"].append(f"get_asset_twas: {e}")

    # 3b. Match impact targets to the asset's misbehaviours (by label)
    ms_payload = []
    if imp_targets:
        try:
            asset = ssm.api_asset.get_asset_in_model(model_webkey, request.asset_id)
            for ms in (getattr(asset, "misbehaviour_sets", None) or {}).values():
                ms_label = (getattr(ms, "misbehaviour_label", None) or getattr(ms, "label", None) or "")
                level = imp_targets.get(ms_label.lower())
                if not level or _set_level_uri(ms.impact_level, level) is None:
                    continue
                ms.impact_level_asserted = True
                ms_payload.append(ms.to_dict())
                summary["applied"]["impacts"].append({"misbehaviour": ms_label, "level": level})
        except Exception as e:
            summary["applied"]["errors"].append(f"get_asset misbehaviours: {e}")

    # 3c. Apply each batch
    if twa_payload:
        try:
            ssm.update_twas_bulk(model_webkey, request.asset_id, twa_payload)
        except Exception as e:
            summary["applied"]["errors"].append(f"twas/bulk: {e}")
    if ms_payload:
        try:
            ssm.update_impact_bulk(model_webkey, ms_payload)
        except Exception as e:
            summary["applied"]["errors"].append(f"impact/bulk: {e}")

    # Record any target properties that didn't match a property on this asset.
    matched = {a["twa"].lower() for a in summary["applied"]["twas"]} | \
              {a["misbehaviour"].lower() for a in summary["applied"]["impacts"]}
    summary["applied"]["unmatched"] = [t["property"] for t in targets if t["property"].lower() not in matched]

    logger.info(f"[trustguard.bind] applied {len(summary['applied']['twas'])} TWAs, "
                f"{len(summary['applied']['impacts'])} impacts, "
                f"{len(summary['applied']['unmatched'])} unmatched, "
                f"{len(summary['applied']['errors'])} errors")
    for _e in summary["applied"]["errors"]:
        logger.warning(f"[trustguard.bind] ERROR DETAIL: {_e}")
    return summary
