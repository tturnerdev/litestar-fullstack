"""Gateway Numbers Controller."""

from __future__ import annotations

from typing import Annotated

from litestar import Controller, get
from litestar.di import Provide
from litestar.params import Parameter

from app.db import models as m
from app.domain.gateway.deps import provide_gateway_connections
from app.domain.gateway.schemas import NumberGatewayResponse
from app.domain.gateway.services import GatewayService


class NumbersGatewayController(Controller):
    """Phone number gateway lookups."""

    tags = ["Gateway - Numbers"]
    dependencies = {
        "gateway_connections": Provide(provide_gateway_connections),
    }

    @get(
        operation_id="GatewayLookupNumber",
        path="/api/gateway/numbers/{phone_number:str}",
    )
    async def get_number_data(
        self,
        gateway_connections: list[m.Connection],
        current_user: m.User,
        phone_number: Annotated[
            str,
            Parameter(title="Phone Number", description="The phone number to look up across all sources."),
        ],
    ) -> NumberGatewayResponse:
        """Look up a phone number across all configured external sources.

        Queries every enabled connection whose provider supports the
        ``numbers`` domain and returns aggregated results.

        Args:
            gateway_connections: Pre-loaded list of connections.
            current_user: The authenticated user.
            phone_number: The phone number to look up.

        Returns:
            NumberGatewayResponse
        """
        svc = GatewayService(connections=gateway_connections)
        sources = await svc.query_number(phone_number)
        return NumberGatewayResponse(
            phone_number=phone_number,
            sources=sources,
        )
