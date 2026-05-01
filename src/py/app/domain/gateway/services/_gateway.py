"""Gateway service — fan-out queries to registered providers."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import msgspec
import structlog

from app.domain.gateway.providers import PROVIDER_REGISTRY
from app.domain.gateway.schemas._common import SourceResult

if TYPE_CHECKING:
    from redis.asyncio import Redis

    from app.db import models as m

logger = structlog.get_logger()

_CACHE_PREFIX = "gateway"


class GatewayService:
    """Orchestrates concurrent queries across external data providers.

    Unlike domain services that wrap a repository, this service has no
    database model of its own.  It receives a pre-loaded list of
    ``Connection`` rows and dispatches queries to the matching provider
    for each connection.

    When a Redis client is provided, results are cached per-connection
    using the key format ``gateway:{provider}:{domain}:{identifier}:{connection_id}``
    with a configurable TTL (default 300 seconds).
    """

    def __init__(
        self,
        connections: list[m.Connection],
        redis: Redis | None = None,
        cache_ttl: int = 300,
    ) -> None:
        self._connections = connections
        self._redis = redis
        self._cache_ttl = cache_ttl

    async def query_number(self, phone_number: str, *, refresh: bool = False) -> dict[str, SourceResult]:
        """Query all providers for information about a phone number.

        Args:
            phone_number: The phone number to look up.
            refresh: If ``True``, bypass the cache and force a fresh query.

        Returns:
            A dict keyed by source identifier with query results.
        """
        return await self._query_all("numbers", "query_number", phone_number, refresh=refresh)

    async def query_extension(self, extension: str, *, refresh: bool = False) -> dict[str, SourceResult]:
        """Query all providers for information about an extension.

        Args:
            extension: The extension number to look up.
            refresh: If ``True``, bypass the cache and force a fresh query.

        Returns:
            A dict keyed by source identifier with query results.
        """
        return await self._query_all("extensions", "query_extension", extension, refresh=refresh)

    async def query_device(self, mac_address: str, *, refresh: bool = False) -> dict[str, SourceResult]:
        """Query all providers for information about a device.

        Args:
            mac_address: The MAC address to look up.
            refresh: If ``True``, bypass the cache and force a fresh query.

        Returns:
            A dict keyed by source identifier with query results.
        """
        return await self._query_all("devices", "query_device", mac_address, refresh=refresh)

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def _cache_key(self, provider: str, domain: str, identifier: str, connection_id: str) -> str:
        """Build a Redis cache key.

        Format: ``gateway:{provider}:{domain}:{identifier}:{connection_id}``
        """
        return f"{_CACHE_PREFIX}:{provider}:{domain}:{identifier}:{connection_id}"

    async def _get_cached(self, key: str) -> SourceResult | None:
        """Return a cached ``SourceResult`` or ``None``."""
        if self._redis is None:
            return None
        try:
            raw = await self._redis.get(key)
        except Exception:
            await logger.awarning("Redis cache read error", cache_key=key, exc_info=True)
            return None
        if raw is None:
            return None
        try:
            return msgspec.json.decode(raw, type=SourceResult)
        except Exception:
            await logger.awarning("Cache deserialization error", cache_key=key, exc_info=True)
            return None

    async def _set_cached(self, key: str, result: SourceResult) -> None:
        """Store a ``SourceResult`` in Redis with the configured TTL."""
        if self._redis is None:
            return
        try:
            raw = msgspec.json.encode(result)
            await self._redis.set(key, raw, ex=self._cache_ttl)
        except Exception:
            await logger.awarning("Redis cache write error", cache_key=key, exc_info=True)

    # ------------------------------------------------------------------
    # Core fan-out logic
    # ------------------------------------------------------------------

    async def _query_all(
        self,
        domain: str,
        method_name: str,
        identifier: str,
        *,
        refresh: bool = False,
    ) -> dict[str, SourceResult]:
        """Fan-out a query to every enabled connection that supports the domain.

        When caching is enabled (Redis client provided), each connection's
        result is checked against the cache before issuing a provider query.
        Cached results are returned immediately unless *refresh* is ``True``.

        Args:
            domain: The query domain (numbers, extensions, devices).
            method_name: The provider method to call.
            identifier: The lookup value to pass to the provider.
            refresh: If ``True``, skip the cache and query providers directly.

        Returns:
            A dict keyed by source identifier with query results.
        """
        sources: dict[str, SourceResult] = {}

        # Determine which connections are eligible
        eligible: list[tuple[m.Connection, str]] = []  # (connection, source_key)
        for conn in self._connections:
            if not conn.is_enabled:
                continue
            provider_cls = PROVIDER_REGISTRY.get(conn.provider)
            if provider_cls is None:
                continue
            if domain not in provider_cls.supported_domains:
                continue
            key = f"{conn.provider}_{conn.id.hex[:8]}"
            eligible.append((conn, key))

        if not eligible:
            return {}

        # Phase 1 — check cache for each eligible connection
        to_query: list[tuple[m.Connection, str]] = []
        for conn, source_key in eligible:
            if refresh:
                to_query.append((conn, source_key))
                continue
            cache_key = self._cache_key(conn.provider, domain, identifier, conn.id.hex)
            cached = await self._get_cached(cache_key)
            if cached is not None:
                sources[source_key] = cached
            else:
                to_query.append((conn, source_key))

        # Phase 2 — fan-out queries for connections with cache misses
        if to_query:
            tasks: dict[str, asyncio.Task[object]] = {}
            conn_map: dict[str, m.Connection] = {}
            for conn, source_key in to_query:
                provider_cls = PROVIDER_REGISTRY.get(conn.provider)
                if provider_cls is None:
                    continue
                provider = provider_cls()
                tasks[source_key] = getattr(provider, method_name)(identifier, conn)
                conn_map[source_key] = conn

            results_list = await asyncio.gather(*tasks.values(), return_exceptions=True)

            for source_key, result in zip(tasks.keys(), results_list, strict=False):
                conn = conn_map[source_key]
                if isinstance(result, Exception):
                    await logger.awarning(
                        "Gateway provider query failed",
                        provider=conn.provider,
                        connection_id=str(conn.id),
                        error=str(result),
                    )
                    sources[source_key] = SourceResult(
                        connection_id=str(conn.id),
                        connection_name=conn.name,
                        status="error",
                        error=str(result),
                    )
                else:
                    sr = SourceResult(
                        connection_id=str(conn.id),
                        connection_name=conn.name,
                        status=result.status,
                        data=result.data,
                        error=result.error,
                    )
                    sources[source_key] = sr
                    # Cache successful results only
                    if sr.status == "ok":
                        cache_key = self._cache_key(conn.provider, domain, identifier, conn.id.hex)
                        await self._set_cached(cache_key, sr)

        return sources
