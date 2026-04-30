"""Gateway Devices Controller."""

from __future__ import annotations

from typing import Annotated

from litestar import Controller, get
from litestar.di import Provide
from litestar.params import Parameter

from app.db import models as m
from app.domain.gateway.deps import provide_gateway_connections
from app.domain.gateway.schemas import DeviceGatewayResponse
from app.domain.gateway.services import GatewayService


class DevicesGatewayController(Controller):
    """Device gateway lookups by MAC address."""

    tags = ["Gateway - Devices"]
    dependencies = {
        "gateway_connections": Provide(provide_gateway_connections),
    }

    @get(
        operation_id="GatewayLookupDevice",
        path="/api/gateway/devices/{mac_address:str}",
    )
    async def get_device_data(
        self,
        gateway_connections: list[m.Connection],
        current_user: m.User,
        mac_address: Annotated[
            str,
            Parameter(title="MAC Address", description="The MAC address to look up across all sources."),
        ],
    ) -> DeviceGatewayResponse:
        """Look up a device by MAC address across all configured external sources.

        Queries every enabled connection whose provider supports the
        ``devices`` domain and returns aggregated results.

        Args:
            gateway_connections: Pre-loaded list of connections.
            current_user: The authenticated user.
            mac_address: The MAC address to look up.

        Returns:
            DeviceGatewayResponse
        """
        svc = GatewayService(connections=gateway_connections)
        sources = await svc.query_device(mac_address)
        return DeviceGatewayResponse(
            mac_address=mac_address,
            sources=sources,
        )
