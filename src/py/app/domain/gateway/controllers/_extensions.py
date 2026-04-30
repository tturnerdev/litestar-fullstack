"""Gateway Extensions Controller."""

from __future__ import annotations

from typing import Annotated

from litestar import Controller, get
from litestar.di import Provide
from litestar.params import Parameter

from app.db import models as m
from app.domain.gateway.deps import provide_gateway_connections
from app.domain.gateway.schemas import ExtensionGatewayResponse
from app.domain.gateway.services import GatewayService


class ExtensionsGatewayController(Controller):
    """Extension gateway lookups."""

    tags = ["Gateway - Extensions"]
    dependencies = {
        "gateway_connections": Provide(provide_gateway_connections),
    }

    @get(
        operation_id="GatewayLookupExtension",
        path="/api/gateway/extensions/{extension_number:str}",
    )
    async def get_extension_data(
        self,
        gateway_connections: list[m.Connection],
        current_user: m.User,
        extension_number: Annotated[
            str,
            Parameter(title="Extension Number", description="The extension to look up across all sources."),
        ],
    ) -> ExtensionGatewayResponse:
        """Look up an extension across all configured external sources.

        Queries every enabled connection whose provider supports the
        ``extensions`` domain and returns aggregated results.

        Args:
            gateway_connections: Pre-loaded list of connections.
            current_user: The authenticated user.
            extension_number: The extension number to look up.

        Returns:
            ExtensionGatewayResponse
        """
        svc = GatewayService(connections=gateway_connections)
        sources = await svc.query_extension(extension_number)
        return ExtensionGatewayResponse(
            extension_number=extension_number,
            sources=sources,
        )
