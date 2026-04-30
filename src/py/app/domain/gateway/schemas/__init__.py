"""Gateway domain schemas."""

from app.domain.gateway.schemas._common import GatewayResponse, SourceResult
from app.domain.gateway.schemas._devices import DeviceGatewayResponse
from app.domain.gateway.schemas._extensions import ExtensionGatewayResponse
from app.domain.gateway.schemas._numbers import NumberGatewayResponse

__all__ = (
    "DeviceGatewayResponse",
    "ExtensionGatewayResponse",
    "GatewayResponse",
    "NumberGatewayResponse",
    "SourceResult",
)
