##///////////////////////////////////////////////////////////////////////
##
## TrustGuard client (PROTOTYPE).
##
## Makes the outbound HTTP request to the TrustGuard service for a given
## asset id and returns its JSON.
##
##///////////////////////////////////////////////////////////////////////

import requests
from fastapi.logger import logger

from app.core.config import TRUSTGUARD_URL


class TrustGuardError(Exception):
    """Raised when the TrustGuard service cannot be reached or returns an error."""


class TrustGuardClient:
    """Thin client around the TrustGuard REST service."""

    def __init__(self, base_url: str = TRUSTGUARD_URL, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def get_asset(self, name: str) -> dict:
        """Fetch TrustGuard's properties for an asset name."""
        url = f"{self.base_url}/assets/{name}"
        logger.info(f"[trustguard] GET {url}")
        try:
            resp = requests.get(url, timeout=self.timeout)
        except requests.RequestException as e:
            raise TrustGuardError(f"could not reach TrustGuard at {url}: {e}") from e

        if resp.status_code != 200:
            raise TrustGuardError(
                f"TrustGuard returned HTTP {resp.status_code} for asset '{name}'")
        try:
            return resp.json()
        except ValueError as e:
            raise TrustGuardError(f"TrustGuard returned invalid JSON: {e}") from e
