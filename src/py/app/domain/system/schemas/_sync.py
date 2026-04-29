"""Sync response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.lib.schema import CamelizedBaseStruct


class SyncResponse(CamelizedBaseStruct, kw_only=True):
    """Response from a sync operation."""

    synced: bool
    domain: str
    field: str
    value: str
    entity: dict[str, Any]
    synced_at: datetime
