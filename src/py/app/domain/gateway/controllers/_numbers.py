"""Gateway Numbers Controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from litestar import Controller, get
from litestar.di import Provide
from litestar.params import Parameter

from app.db import models as m
from app.domain.gateway.deps import provide_gateway_connections, provide_gateway_redis
from app.domain.gateway.schemas import NumberGatewayResponse
from app.domain.gateway.services import GatewayService
from app.lib.settings import get_settings

if TYPE_CHECKING:
    from redis.asyncio import Redis


class NumbersGatewayController(Controller):
    """Phone number gateway lookups."""

    tags = ["Gateway - Numbers"]
    dependencies = {
        "gateway_connections": Provide(provide_gateway_connections),
        "gateway_redis": Provide(provide_gateway_redis),
    }

    @get(
        operation_id="GatewayLookupNumber",
        path="/api/gateway/numbers/{phone_number:str}",
    )
    async def get_number_data(
        self,
        gateway_connections: list[m.Connection],
        gateway_redis: Redis,
        current_user: m.User,
        phone_number: Annotated[
            str,
            Parameter(title="Phone Number", description="The phone number to look up across all sources."),
        ],
        refresh: Annotated[
            bool,
            Parameter(query="refresh", description="Bypass cache and force a fresh query.", required=False),
        ] = False,
    ) -> NumberGatewayResponse:
        """Look up a phone number across all configured external sources.

        Queries every enabled connection whose provider supports the
        ``numbers`` domain and returns aggregated results.

        Args:
            gateway_connections: Pre-loaded list of connections.
            gateway_redis: Async Redis client for caching.
            current_user: The authenticated user.
            phone_number: The phone number to look up.
            refresh: If ``True``, bypass the cache.

        Returns:
            NumberGatewayResponse
        """
        settings = get_settings()
        svc = GatewayService(
            connections=gateway_connections,
            redis=gateway_redis,
            cache_ttl=settings.gateway.DEFAULT_CACHE_TTL,
        )
        sources = await svc.query_number(phone_number, refresh=refresh)
        return NumberGatewayResponse(
            phone_number=phone_number,
            sources=sources,
        )
