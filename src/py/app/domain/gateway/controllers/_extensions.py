"""Gateway Extensions Controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from litestar import Controller, get
from litestar.di import Provide
from litestar.params import Parameter

from app.db import models as m
from app.domain.gateway.deps import provide_gateway_connections, provide_gateway_redis
from app.domain.gateway.schemas import ExtensionGatewayResponse
from app.domain.gateway.services import GatewayService
from app.lib.settings import get_settings

if TYPE_CHECKING:
    from redis.asyncio import Redis


class ExtensionsGatewayController(Controller):
    """Extension gateway lookups."""

    tags = ["Gateway - Extensions"]
    dependencies = {
        "gateway_connections": Provide(provide_gateway_connections),
        "gateway_redis": Provide(provide_gateway_redis),
    }

    @get(
        operation_id="GatewayLookupExtension",
        path="/api/gateway/extensions/{extension_number:str}",
    )
    async def get_extension_data(
        self,
        gateway_connections: list[m.Connection],
        gateway_redis: Redis,
        current_user: m.User,
        extension_number: Annotated[
            str,
            Parameter(title="Extension Number", description="The extension to look up across all sources."),
        ],
        refresh: Annotated[
            bool,
            Parameter(query="refresh", description="Bypass cache and force a fresh query.", required=False),
        ] = False,
    ) -> ExtensionGatewayResponse:
        """Look up an extension across all configured external sources.

        Queries every enabled connection whose provider supports the
        ``extensions`` domain and returns aggregated results.

        Args:
            gateway_connections: Pre-loaded list of connections.
            gateway_redis: Async Redis client for caching.
            current_user: The authenticated user.
            extension_number: The extension number to look up.
            refresh: If ``True``, bypass the cache.

        Returns:
            ExtensionGatewayResponse
        """
        settings = get_settings()
        svc = GatewayService(
            connections=gateway_connections,
            redis=gateway_redis,
            cache_ttl=settings.gateway.DEFAULT_CACHE_TTL,
        )
        sources = await svc.query_extension(extension_number, refresh=refresh)
        return ExtensionGatewayResponse(
            extension_number=extension_number,
            sources=sources,
        )
