"""Gateway Devices Controller."""

from __future__ import annotations

from typing import Annotated

from litestar import Controller, get
from litestar.di import Provide
from litestar.params import Parameter

from app.db import models as m
from app.domain.gateway.deps import provide_gateway_connections, provide_gateway_redis
from app.domain.gateway.schemas import DeviceGatewayResponse
from app.domain.gateway.services import GatewayService
from redis.asyncio import Redis
from app.lib.settings import get_settings


class DevicesGatewayController(Controller):
    """Device gateway lookups by MAC address."""

    tags = ["Gateway - Devices"]
    dependencies = {
        "gateway_connections": Provide(provide_gateway_connections),
        "gateway_redis": Provide(provide_gateway_redis),
    }

    @get(
        operation_id="GatewayLookupDevice",
        path="/api/gateway/devices/{mac_address:str}",
    )
    async def get_device_data(
        self,
        gateway_connections: list[m.Connection],
        gateway_redis: Redis,
        current_user: m.User,
        mac_address: Annotated[
            str,
            Parameter(title="MAC Address", description="The MAC address to look up across all sources."),
        ],
        refresh: Annotated[
            bool,
            Parameter(query="refresh", description="Bypass cache and force a fresh query.", required=False),
        ] = False,
    ) -> DeviceGatewayResponse:
        """Look up a device by MAC address across all configured external sources.

        Queries every enabled connection whose provider supports the
        ``devices`` domain and returns aggregated results.

        Args:
            gateway_connections: Pre-loaded list of connections.
            gateway_redis: Async Redis client for caching.
            current_user: The authenticated user.
            mac_address: The MAC address to look up.
            refresh: If ``True``, bypass the cache.

        Returns:
            DeviceGatewayResponse
        """
        settings = get_settings()
        svc = GatewayService(
            connections=gateway_connections,
            redis=gateway_redis,
            cache_ttl=settings.gateway.DEFAULT_CACHE_TTL,
        )
        sources = await svc.query_device(mac_address, refresh=refresh)
        return DeviceGatewayResponse(
            mac_address=mac_address,
            sources=sources,
        )
