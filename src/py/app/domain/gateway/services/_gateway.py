"""Gateway service — fan-out queries to registered providers."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import structlog

from app.domain.gateway.providers import PROVIDER_REGISTRY
from app.domain.gateway.schemas._common import SourceResult

if TYPE_CHECKING:
    from app.db import models as m

logger = structlog.get_logger()


class GatewayService:
    """Orchestrates concurrent queries across external data providers.

    Unlike domain services that wrap a repository, this service has no
    database model of its own.  It receives a pre-loaded list of
    ``Connection`` rows and dispatches queries to the matching provider
    for each connection.
    """

    def __init__(self, connections: list[m.Connection]) -> None:
        self._connections = connections

    async def query_number(self, phone_number: str) -> dict[str, SourceResult]:
        """Query all providers for information about a phone number.

        Args:
            phone_number: The phone number to look up.

        Returns:
            A dict keyed by source identifier with query results.
        """
        return await self._query_all("numbers", "query_number", phone_number)

    async def query_extension(self, extension: str) -> dict[str, SourceResult]:
        """Query all providers for information about an extension.

        Args:
            extension: The extension number to look up.

        Returns:
            A dict keyed by source identifier with query results.
        """
        return await self._query_all("extensions", "query_extension", extension)

    async def query_device(self, mac_address: str) -> dict[str, SourceResult]:
        """Query all providers for information about a device.

        Args:
            mac_address: The MAC address to look up.

        Returns:
            A dict keyed by source identifier with query results.
        """
        return await self._query_all("devices", "query_device", mac_address)

    async def _query_all(self, domain: str, method_name: str, identifier: str) -> dict[str, SourceResult]:
        """Fan-out a query to every enabled connection that supports the domain.

        Args:
            domain: The query domain (numbers, extensions, devices).
            method_name: The provider method to call.
            identifier: The lookup value to pass to the provider.

        Returns:
            A dict keyed by source identifier with query results.
        """
        tasks: dict[m.Connection, asyncio.Task[object]] = {}
        for conn in self._connections:
            if not conn.is_enabled:
                continue
            provider_cls = PROVIDER_REGISTRY.get(conn.provider)
            if provider_cls is None:
                continue
            if domain not in provider_cls.supported_domains:
                continue
            provider = provider_cls()
            tasks[conn] = getattr(provider, method_name)(identifier, conn)

        if not tasks:
            return {}

        results_list = await asyncio.gather(*tasks.values(), return_exceptions=True)
        sources: dict[str, SourceResult] = {}
        for conn, result in zip(tasks.keys(), results_list, strict=False):
            # Build a unique key per connection instance
            key = f"{conn.provider}_{conn.id.hex[:8]}"
            if isinstance(result, Exception):
                await logger.awarning(
                    "Gateway provider query failed",
                    provider=conn.provider,
                    connection_id=str(conn.id),
                    error=str(result),
                )
                sources[key] = SourceResult(
                    connection_id=str(conn.id),
                    connection_name=conn.name,
                    status="error",
                    error=str(result),
                )
            else:
                sources[key] = SourceResult(
                    connection_id=str(conn.id),
                    connection_name=conn.name,
                    status=result.status,
                    data=result.data,
                    error=result.error,
                )
        return sources
