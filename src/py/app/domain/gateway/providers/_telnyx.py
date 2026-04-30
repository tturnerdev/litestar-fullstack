"""Telnyx REST API gateway provider."""

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

_BASE_URL = "https://api.telnyx.com/v2"


@register_provider
class TelnyxProvider(GatewayProvider):
    """Gateway provider for the Telnyx REST API.

    Supports phone number lookups via Telnyx's ``/v2/phone_numbers`` endpoint.
    Extensions and devices are not applicable to a carrier and return
    ``not_supported``.
    """

    provider_name: ClassVar[str] = "telnyx"
    supported_domains: ClassVar[set[str]] = {"numbers"}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_api_key(connection: m.Connection) -> str:
        """Extract the API key from connection credentials."""
        creds = connection.credentials or {}
        api_key = creds.get("api_key")
        if not api_key:
            msg = "Telnyx connection missing api_key in credentials"
            raise ValueError(msg)
        return api_key

    @staticmethod
    def _get_timeout(connection: m.Connection) -> float:
        """Return the request timeout configured for this connection."""
        settings = connection.settings or {}
        return float(settings.get("timeout", 10))

    @asynccontextmanager
    async def _client(self, connection: m.Connection) -> AsyncIterator[httpx.AsyncClient]:
        """Build a pre-configured ``httpx.AsyncClient`` for Telnyx."""
        api_key = self._get_api_key(connection)
        timeout = self._get_timeout(connection)
        async with httpx.AsyncClient(
            base_url=_BASE_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=httpx.Timeout(timeout),
        ) as client:
            yield client

    def _handle_error(self, exc: Exception) -> ProviderResult:
        """Translate common exceptions into a ``ProviderResult``."""
        if isinstance(exc, httpx.TimeoutException):
            return ProviderResult(status="timeout", error=str(exc))
        return ProviderResult(status="error", error=str(exc))

    @staticmethod
    def _handle_status_code(response: httpx.Response) -> ProviderResult | None:
        """Return an error result for auth failures, or ``None`` to continue."""
        if response.status_code in (401, 403):
            return ProviderResult(
                status="auth_failed",
                error=f"Telnyx returned {response.status_code}",
            )
        return None

    # ------------------------------------------------------------------
    # Number queries
    # ------------------------------------------------------------------

    async def query_number(self, phone_number: str, connection: m.Connection) -> ProviderResult:
        """Look up a phone number in Telnyx.

        The incoming *phone_number* is expected as digits only (e.g.
        ``15551234567``). We prepend ``+`` for E.164 formatting as required
        by the Telnyx API.
        """
        e164 = f"+{phone_number}" if not phone_number.startswith("+") else phone_number

        try:
            async with self._client(connection) as client:
                # ----- primary number lookup -----
                resp = await client.get(
                    "/v2/phone_numbers",
                    params={"filter[phone_number]": e164, "page[size]": 1},
                )

                if (auth_err := self._handle_status_code(resp)) is not None:
                    return auth_err
                resp.raise_for_status()

                body = resp.json()
                records: list[dict[str, Any]] = body.get("data", [])

                if not records:
                    return ProviderResult(
                        status="ok",
                        data={"found": False, "phone_number": e164},
                    )

                number = records[0]

                # ----- optional messaging info -----
                messaging = await self._fetch_messaging(client, number.get("id"))

                return ProviderResult(
                    status="ok",
                    data=self._normalize_number(number, messaging),
                )
        except Exception as exc:
            await logger.awarning("telnyx_query_number_failed", phone_number=e164, error=str(exc))
            return self._handle_error(exc)

    async def _fetch_messaging(
        self,
        client: httpx.AsyncClient,
        number_id: str | None,
    ) -> dict[str, Any] | None:
        """Fetch messaging profile for a phone number resource.

        Returns ``None`` silently on any failure so that a missing or
        inaccessible messaging profile never blocks the main lookup.
        """
        if not number_id:
            return None
        try:
            resp = await client.get(f"/v2/phone_numbers/{number_id}/messaging")
            if resp.is_success:
                return resp.json().get("data")
        except Exception:
            await logger.adebug("telnyx_messaging_lookup_failed", number_id=number_id)
        return None

    @staticmethod
    def _normalize_number(
        number: dict[str, Any],
        messaging: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Build the normalized result dict for a found phone number."""
        return {
            "found": True,
            "phone_number": number.get("phone_number"),
            "status": number.get("status"),
            "connection_name": number.get("connection_name"),
            "connection_id": number.get("connection_id"),
            "purchased_at": number.get("purchased_at"),
            "e911": {
                "enabled": number.get("emergency_enabled", False),
                "address_id": number.get("emergency_address_id"),
            },
            "cnam": {
                "listing_enabled": number.get("cnam_listing_enabled", False),
                "caller_id_name_enabled": number.get("caller_id_name_enabled", False),
            },
            "call_forwarding_enabled": number.get("call_forwarding_enabled", False),
            "tags": number.get("tags", []),
            "messaging": messaging,
        }

    # ------------------------------------------------------------------
    # Extension / device queries (not applicable for a carrier)
    # ------------------------------------------------------------------

    async def query_extension(self, extension: str, connection: m.Connection) -> ProviderResult:
        """Extensions are a PBX concept -- Telnyx does not manage them."""
        return ProviderResult(status="not_supported", error="Telnyx does not manage extensions")

    async def query_device(self, mac_address: str, connection: m.Connection) -> ProviderResult:
        """Devices are a PBX concept -- Telnyx does not manage them."""
        return ProviderResult(status="not_supported", error="Telnyx does not manage devices")

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    async def health_check(self, connection: m.Connection) -> tuple[bool, str | None]:
        """Verify connectivity by listing phone numbers with page size 1."""
        try:
            async with self._client(connection) as client:
                resp = await client.get("/v2/phone_numbers", params={"page[size]": 1})
                resp.raise_for_status()
                return True, None
        except Exception as exc:
            return False, str(exc)
