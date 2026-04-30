"""Number gateway response schemas."""

from __future__ import annotations

from typing import Any

from app.domain.gateway.schemas._common import SourceResult
from app.lib.schema import CamelizedBaseStruct


class NumberGatewayResponse(CamelizedBaseStruct):
    """Aggregated gateway response for a phone number lookup."""

    phone_number: str
    sources: dict[str, SourceResult] = {}
    internal: dict[str, Any] | None = None
