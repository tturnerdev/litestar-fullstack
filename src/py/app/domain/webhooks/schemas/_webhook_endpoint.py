"""Webhook endpoint schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

import msgspec
from msgspec import Meta

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
    last_validated_at: datetime | None = None
    validation_status: str | None = None
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
    validation_status: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class WebhookEndpointCreate(CamelizedBaseStruct):
    """Webhook endpoint create schema."""

    url: Annotated[str, Meta(min_length=1, max_length=2048)]
    description: Annotated[str, Meta(max_length=1000)] | None = None
    events: list[str] = []
    is_active: bool = True
    secret: Annotated[str, Meta(max_length=255)] | None = None
    headers: dict[str, Any] | None = None
    team_id: UUID | None = None


class WebhookEndpointUpdate(CamelizedBaseStruct):
    """Webhook endpoint update schema."""

    url: Annotated[str, Meta(min_length=1, max_length=2048)] | None = msgspec.UNSET  # type: ignore[assignment]
    description: Annotated[str, Meta(max_length=1000)] | None = msgspec.UNSET  # type: ignore[assignment]
    events: list[str] | None = msgspec.UNSET  # type: ignore[assignment]
    is_active: bool | None = msgspec.UNSET  # type: ignore[assignment]
    secret: Annotated[str, Meta(max_length=255)] | None = msgspec.UNSET  # type: ignore[assignment]
    headers: dict[str, Any] | None = msgspec.UNSET  # type: ignore[assignment]
