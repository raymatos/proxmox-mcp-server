"""Proxmox VE API client with token and password auth."""

from __future__ import annotations

import os
import sys
from typing import Any, Optional

import httpx

PROXMOX_HOST = os.getenv("PROXMOX_HOST", "")
PROXMOX_PORT = os.getenv("PROXMOX_PORT", "8006")
PROXMOX_USER = os.getenv("PROXMOX_USER", "")
PROXMOX_TOKEN_NAME = os.getenv("PROXMOX_TOKEN_NAME", "")
PROXMOX_TOKEN_VALUE = os.getenv("PROXMOX_TOKEN_VALUE", "")
PROXMOX_PASSWORD = os.getenv("PROXMOX_PASSWORD", "")
PROXMOX_VERIFY_SSL = os.getenv("PROXMOX_VERIFY_SSL", "false").lower() == "true"


def _validate_config() -> None:
    if not PROXMOX_HOST or not PROXMOX_USER:
        print("Error: PROXMOX_HOST and PROXMOX_USER must be set", file=sys.stderr)
        sys.exit(1)
    use_token = PROXMOX_TOKEN_NAME and PROXMOX_TOKEN_VALUE
    use_password = PROXMOX_PASSWORD
    if not use_token and not use_password:
        print(
            "Error: Either PROXMOX_TOKEN_NAME+PROXMOX_TOKEN_VALUE or PROXMOX_PASSWORD must be set",
            file=sys.stderr,
        )
        sys.exit(1)


def _proxmox_value(value: Any) -> Any:
    """Convert a single value to the form the Proxmox API accepts.

    httpx renders Python ``True``/``False`` as the strings ``"true"``/``"false"``
    in both form bodies and query strings, but Proxmox's ``-boolean`` type only
    accepts ``1``/``0`` and rejects anything else with a 400. Booleans are checked
    before any int handling because ``isinstance(True, int)`` is also true.
    """
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, list):
        return [_proxmox_value(item) for item in value]
    return value


def _proxmox_params(
    data: Optional[dict[str, Any]],
) -> Optional[dict[str, Any]]:
    """Serialize an outgoing parameter dict for the Proxmox API.

    Applied at this single choke point so every tool benefits: ~168 boolean
    parameters are declared across the tool modules, and each one used to fail
    with a 400 (proven by elimination on clone_vm(full=) and
    migrate_vm(with-local-disks=), which succeed with the boolean removed).
    """
    if not data:
        return data
    return {key: _proxmox_value(value) for key, value in data.items()}


class ProxmoxClient:
    def __init__(self) -> None:
        self.base_url = f"https://{PROXMOX_HOST}:{PROXMOX_PORT}/api2/json"
        self.client = httpx.AsyncClient(verify=PROXMOX_VERIFY_SSL, timeout=30.0)
        self.ticket: Optional[str] = None
        self.csrf_token: Optional[str] = None
        self.token: Optional[str] = None

    async def authenticate(self) -> None:
        use_token = PROXMOX_TOKEN_NAME and PROXMOX_TOKEN_VALUE
        if use_token:
            self.token = f"PVEAPIToken={PROXMOX_USER}!{PROXMOX_TOKEN_NAME}={PROXMOX_TOKEN_VALUE}"
            print(f"✓ Token auth: {PROXMOX_USER}!{PROXMOX_TOKEN_NAME}", file=sys.stderr)
        else:
            response = await self.client.post(
                f"{self.base_url}/access/ticket",
                data={"username": PROXMOX_USER, "password": PROXMOX_PASSWORD},
            )
            response.raise_for_status()
            data = response.json()["data"]
            self.ticket = data["ticket"]
            self.csrf_token = data["CSRFPreventionToken"]
            print(f"✓ Ticket auth: {PROXMOX_USER}", file=sys.stderr)

    def _headers(self, method: str) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = self.token
        elif self.ticket:
            headers["Cookie"] = f"PVEAuthCookie={self.ticket}"
            if method != "GET":
                headers["CSRFPreventionToken"] = self.csrf_token or ""
        return headers

    async def request(
        self,
        method: str,
        path: str,
        data: Optional[dict[str, Any]] = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        headers = self._headers(method)
        data = _proxmox_params(data)
        if method == "GET":
            response = await self.client.get(url, headers=headers, params=data)
        elif method == "POST":
            response = await self.client.post(url, headers=headers, data=data)
        elif method == "PUT":
            response = await self.client.put(url, headers=headers, data=data)
        elif method == "DELETE":
            response = await self.client.delete(url, headers=headers, params=data)
        else:
            raise ValueError(f"Unsupported method: {method}")
        response.raise_for_status()
        return response.json()

    async def get(self, path: str, params: Optional[dict[str, Any]] = None) -> Any:
        return await self.request("GET", path, params)

    async def post(self, path: str, data: Optional[dict[str, Any]] = None) -> Any:
        return await self.request("POST", path, data)

    async def put(self, path: str, data: Optional[dict[str, Any]] = None) -> Any:
        return await self.request("PUT", path, data)

    async def delete(self, path: str, params: Optional[dict[str, Any]] = None) -> Any:
        return await self.request("DELETE", path, params)

    async def close(self) -> None:
        await self.client.aclose()
