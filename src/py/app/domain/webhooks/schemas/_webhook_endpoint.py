"""Webhook endpoint schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

import msgspec

from app.lib.schema import CamelizedBaseStruct


class WebhookEndpoint(CamelizedBaseStruct):
    """Webhook endpoint detail schema."""

    id: UUID
    url: str
    description: str | None = None
    events: list[str] = []
    is_active: bool = True
    headers: dict[str, Any] | None = None
    team_id: UUID | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class WebhookEndpointList(CamelizedBaseStruct):
    """Webhook endpoint list schema (lighter weight)."""

    id: UUID
    url: str
    description: str | None = None
    events: list[str] = []
    is_active: bool = True
    team_id: UUID | None = None
    created_at: datetime | None = None


class WebhookEndpointCreate(CamelizedBaseStruct):
    """Webhook endpoint create schema."""

    url: str
    description: str | None = None
    events: list[str] = []
    is_active: bool = True
    secret: str | None = None
    headers: dict[str, Any] | None = None
    team_id: UUID | None = None


class WebhookEndpointUpdate(CamelizedBaseStruct):
    """Webhook endpoint update schema."""

    url: str | None = msgspec.UNSET  # type: ignore[assignment]
    description: str | None = msgspec.UNSET  # type: ignore[assignment]
    events: list[str] | None = msgspec.UNSET  # type: ignore[assignment]
    is_active: bool | None = msgspec.UNSET  # type: ignore[assignment]
    secret: str | None = msgspec.UNSET  # type: ignore[assignment]
    headers: dict[str, Any] | None = msgspec.UNSET  # type: ignore[assignment]
