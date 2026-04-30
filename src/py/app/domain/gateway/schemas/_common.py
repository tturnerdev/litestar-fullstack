"""Common gateway response schemas."""

from __future__ import annotations

from typing import Any

from app.lib.schema import CamelizedBaseStruct


class SourceResult(CamelizedBaseStruct):
    """Result from a single external data source."""

    connection_id: str
    connection_name: str
    status: str  # ok, error, timeout, auth_failed, not_supported
    data: dict[str, Any] | None = None
    error: str | None = None


class GatewayResponse(CamelizedBaseStruct):
    """Generic gateway aggregation response."""

    sources: dict[str, SourceResult] = {}
    internal: dict[str, Any] | None = None
