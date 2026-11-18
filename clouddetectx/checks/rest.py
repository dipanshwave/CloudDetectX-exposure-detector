"""Minimal read-only REST clients for Azure Resource Manager and Google Cloud APIs.

Used for account-wide checks so we don't need a separate SDK package per service.
"""

from __future__ import annotations

import time


class RestError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


class ArmClient:
    """Azure Resource Manager GET with paging, using an azure-identity credential."""

    BASE = "https://management.azure.com"

    def __init__(self, credential, timeout: float = 30.0):
        import requests

        self.credential = credential
        self.timeout = timeout
        self.http = requests.Session()
        self._token = None
        self._expires = 0.0

    def _headers(self) -> dict:
        if not self._token or self._expires - time.time() < 120:
            tok = self.credential.get_token(f"{self.BASE}/.default")
            self._token, self._expires = tok.token, float(tok.expires_on)
        return {"Authorization": f"Bearer {self._token}"}

    def get(self, path: str, api_version: str) -> dict:
        url = path if path.startswith("http") else f"{self.BASE}{path}"
        resp = self.http.get(url, params=None if "api-version=" in url else {"api-version": api_version},
                             headers=self._headers(), timeout=self.timeout)
        if resp.status_code >= 400:
            try:
                err = resp.json().get("error", {})
                msg = f"{err.get('code')}: {err.get('message', '')[:200]}"
            except ValueError:
                msg = resp.text[:200]
            raise RestError(resp.status_code, msg)
        return resp.json()

    def list(self, path: str, api_version: str, limit: int = 5000) -> list[dict]:
        out, page = [], self.get(path, api_version)
        while True:
            out += page.get("value", [])
            nxt = page.get("nextLink")
            if not nxt or len(out) >= limit:
                return out
            page = self.get(nxt, api_version)


class GcpRest:
    """Google Cloud REST GET/POST with paging, using Application Default Credentials."""

    def __init__(self, credentials=None, timeout: float = 30.0):
        import google.auth
        from google.auth.transport.requests import AuthorizedSession

        if credentials is None:
            credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        self.http = AuthorizedSession(credentials)
        self.timeout = timeout

    def _check(self, resp) -> dict:
        if resp.status_code >= 400:
            try:
                err = resp.json().get("error", {})
                msg = f"{err.get('status') or err.get('code')}: {str(err.get('message', ''))[:200]}"
            except ValueError:
                msg = resp.text[:200]
            raise RestError(resp.status_code, msg)
        return resp.json() if resp.content else {}

    def get(self, url: str, params: dict | None = None) -> dict:
        return self._check(self.http.get(url, params=params, timeout=self.timeout))

    def post(self, url: str, body: dict) -> dict:
        return self._check(self.http.post(url, json=body, timeout=self.timeout))

    def list(self, url: str, key: str, params: dict | None = None, limit: int = 5000) -> list[dict]:
        params, out = dict(params or {}), []
        while True:
            page = self.get(url, params)
            out += page.get(key, [])
            token = page.get("nextPageToken")
            if not token or len(out) >= limit:
                return out
            params["pageToken"] = token
