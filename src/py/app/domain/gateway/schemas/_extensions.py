"""Extension gateway response schemas."""

from __future__ import annotations

from typing import Any

from app.domain.gateway.schemas._common import SourceResult
from app.lib.schema import CamelizedBaseStruct


class ExtensionGatewayResponse(CamelizedBaseStruct):
    """Aggregated gateway response for an extension lookup."""

    extension_number: str
    sources: dict[str, SourceResult] = {}
    internal: dict[str, Any] | None = None
