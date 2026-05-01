"""Unifi Network gateway provider."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, ClassVar

import httpx
import structlog

from app.db import models as m
from app.domain.gateway.providers._base import GatewayProvider, ProviderResult
from app.domain.gateway.providers import register_provider

logger = structlog.get_logger()


@register_provider
class UnifiProvider(GatewayProvider):
    """Gateway provider for Unifi Network Controllers.

    Queries Unifi consoles via the Integration API to look up network
    client data by MAC address.  Numbers and extensions are not
    applicable and return ``not_supported``.
    """

    provider_name: ClassVar[str] = "unifi"
    supported_domains: ClassVar[set[str]] = {"devices"}

    @staticmethod
    def _get_api_key(connection: m.Connection) -> str:
        creds = connection.credentials or {}
        api_key = creds.get("api_key")
        if not api_key:
            msg = "Unifi connection missing api_key in credentials"
            raise ValueError(msg)
        return api_key

    @staticmethod
    def _get_timeout(connection: m.Connection) -> float:
        settings = connection.settings or {}
        return float(settings.get("timeout", 10))

    @staticmethod
    def _get_verify_ssl(connection: m.Connection) -> bool:
        settings = connection.settings or {}
        return bool(settings.get("verify_ssl", False))

    @staticmethod
    def _base_url(connection: m.Connection) -> str:
        host = connection.host or ""
        port = connection.port
        scheme = "https"
        base = f"{scheme}://{host}"
        if port and port != 443:
            base = f"{base}:{port}"
        return f"{base}/proxy/network/integration/v1"

    @asynccontextmanager
    async def _client(self, connection: m.Connection) -> AsyncIterator[httpx.AsyncClient]:
        api_key = self._get_api_key(connection)
        timeout = self._get_timeout(connection)
        verify = self._get_verify_ssl(connection)
        async with httpx.AsyncClient(
            base_url=self._base_url(connection),
            headers={
                "X-API-KEY": api_key,
                "Accept": "application/json",
            },
            timeout=httpx.Timeout(timeout),
            verify=verify,
        ) as client:
            yield client

    def _handle_error(self, exc: Exception) -> ProviderResult:
        if isinstance(exc, httpx.TimeoutException):
            return ProviderResult(status="timeout", error=str(exc))
        return ProviderResult(status="error", error=str(exc))

    @staticmethod
    def _handle_status_code(response: httpx.Response) -> ProviderResult | None:
        if response.status_code in (401, 403):
            return ProviderResult(
                status="auth_failed",
                error=f"Unifi returned {response.status_code}",
            )
        return None

    @staticmethod
    def _normalize_mac(mac: str) -> str:
        """Normalize MAC to uppercase colon-separated format (AA:BB:CC:DD:EE:FF)."""
        cleaned = mac.upper().replace("-", "").replace(":", "").replace(".", "")
        if len(cleaned) != 12:
            return mac.upper()
        return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))

    async def query_device(self, mac_address: str, connection: m.Connection) -> ProviderResult:
        """Look up a network client by MAC address across all Unifi sites."""
        normalized_mac = self._normalize_mac(mac_address)

        try:
            async with self._client(connection) as client:
                sites = await self._get_sites(client)
                if sites is None:
                    return ProviderResult(status="error", error="Failed to retrieve Unifi sites")

                for site in sites:
                    site_id = site.get("_id") or site.get("id")
                    if not site_id:
                        continue

                    result = await self._find_client_in_site(client, site_id, site, normalized_mac)
                    if result is not None:
                        return result

                return ProviderResult(
                    status="ok",
                    data={"found": False, "mac_address": normalized_mac},
                )
        except Exception as exc:
            await logger.awarning("unifi_query_device_failed", mac_address=normalized_mac, error=str(exc))
            return self._handle_error(exc)

    async def _get_sites(self, client: httpx.AsyncClient) -> list[dict[str, Any]] | None:
        resp = await client.get("/sites")
        if (auth_err := self._handle_status_code(resp)) is not None:
            return None
        resp.raise_for_status()
        body = resp.json()
        return body.get("data", body) if isinstance(body, dict) else body

    async def _find_client_in_site(
        self,
        client: httpx.AsyncClient,
        site_id: str,
        site: dict[str, Any],
        mac_address: str,
    ) -> ProviderResult | None:
        """Search for a client with the given MAC in a single site. Returns None if not found."""
        resp = await client.get(
            f"/sites/{site_id}/clients",
            params={"filter": f"macAddress.eq('{mac_address}')"},
        )
        if (auth_err := self._handle_status_code(resp)) is not None:
            return auth_err
        if not resp.is_success:
            return None

        body = resp.json()
        clients = body.get("data", body) if isinstance(body, dict) else body
        if not clients:
            return None

        found_client = clients[0] if isinstance(clients, list) else clients
        client_id = found_client.get("_id") or found_client.get("id")

        detail = found_client
        if client_id:
            detail = await self._get_client_detail(client, site_id, client_id) or found_client

        return ProviderResult(
            status="ok",
            data=self._normalize_client(detail, site),
        )

    async def _get_client_detail(
        self,
        client: httpx.AsyncClient,
        site_id: str,
        client_id: str,
    ) -> dict[str, Any] | None:
        try:
            resp = await client.get(f"/sites/{site_id}/clients/{client_id}")
            if resp.is_success:
                body = resp.json()
                return body.get("data", body) if isinstance(body, dict) else body
        except Exception:
            await logger.adebug("unifi_client_detail_failed", site_id=site_id, client_id=client_id)
        return None

    @staticmethod
    def _normalize_client(client_data: dict[str, Any], site: dict[str, Any]) -> dict[str, Any]:
        return {
            "found": True,
            "mac_address": client_data.get("macAddress") or client_data.get("mac"),
            "hostname": client_data.get("hostname") or client_data.get("name"),
            "display_name": client_data.get("name") or client_data.get("hostname"),
            "ip_address": client_data.get("ipAddress") or client_data.get("ip"),
            "connected": client_data.get("isConnected", client_data.get("connected")),
            "network": {
                "vlan": client_data.get("vlan"),
                "network_name": client_data.get("networkName") or client_data.get("network"),
                "interface": client_data.get("type") or client_data.get("connectionType"),
                "wifi_experience": client_data.get("wifiExperience"),
                "signal_strength": client_data.get("signalStrength") or client_data.get("rssi"),
                "channel": client_data.get("channel"),
                "essid": client_data.get("essid"),
                "ap_name": client_data.get("apName") or client_data.get("accessPointName"),
                "ap_mac": client_data.get("apMac") or client_data.get("accessPointMac"),
                "switch_name": client_data.get("switchName"),
                "switch_port": client_data.get("switchPort"),
            },
            "traffic": {
                "tx_bytes": client_data.get("txBytes") or client_data.get("tx_bytes"),
                "rx_bytes": client_data.get("rxBytes") or client_data.get("rx_bytes"),
                "uptime": client_data.get("uptime"),
            },
            "device_info": {
                "oui": client_data.get("oui"),
                "os_name": client_data.get("osName") or client_data.get("os_name"),
                "device_type": client_data.get("devIdOverride") or client_data.get("deviceType"),
                "model": client_data.get("model"),
                "fingerprint": client_data.get("fingerprint"),
            },
            "site": {
                "id": site.get("_id") or site.get("id"),
                "name": site.get("name") or site.get("desc"),
            },
            "last_seen": client_data.get("lastSeen") or client_data.get("last_seen"),
            "first_seen": client_data.get("firstSeen") or client_data.get("first_seen"),
        }

    async def query_number(self, phone_number: str, connection: m.Connection) -> ProviderResult:
        return ProviderResult(status="not_supported", error="Unifi does not manage phone numbers")

    async def query_extension(self, extension: str, connection: m.Connection) -> ProviderResult:
        return ProviderResult(status="not_supported", error="Unifi does not manage extensions")

    async def health_check(self, connection: m.Connection) -> tuple[bool, str | None]:
        try:
            async with self._client(connection) as client:
                resp = await client.get("/sites")
                resp.raise_for_status()
                return True, None
        except Exception as exc:
            return False, str(exc)
