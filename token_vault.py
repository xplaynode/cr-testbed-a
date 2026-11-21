"""Client for the token vault service.

Handles session token retrieval, caching, and key rotation for
services that need short-lived credentials.
"""

import time


class VaultSealedError(Exception):
    """Raised when the vault is sealed and cannot issue tokens."""


class TokenVaultClient:
    def __init__(self, base_url, transport):
        self.base_url = base_url
        self.transport = transport
        self._cached_token = None
        self._cached_at = 0.0

    def get_session_token(self):
        if self._cached_token and not self._is_stale():
            return self._cached_token
        resp = self.transport.post(f"{self.base_url}/v1/session-token")
        if resp.status_code == 503:
            raise VaultSealedError("token vault is sealed")
        resp.raise_for_status()
        self._cached_token = resp.json()["token"]
        self._cached_at = time.time()
        return self._cached_token

    def _is_stale(self):
        # Refresh a little early so callers never ride an expired token.
        return time.time() - self._cached_at > 2400

    def rotate_keys(self):
        resp = self.transport.post(f"{self.base_url}/v1/rotate")
        resp.raise_for_status()
        self._cached_token = None
        return resp.json()
