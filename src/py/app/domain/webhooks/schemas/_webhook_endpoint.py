"""Webhook endpoint schemas."""

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct
from app.lib.validation import validate_url


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
    description: Annotated[str, Meta(min_length=1, max_length=1000)] | None = None
    events: list[str] = []
    is_active: bool = True
    secret: Annotated[str, Meta(min_length=1, max_length=255)] | None = None
    headers: dict[str, Any] | None = None
    team_id: UUID | None = None

    def __post_init__(self) -> None:
        self.url = validate_url(self.url)


class WebhookEndpointUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Webhook endpoint update schema."""

    url: Annotated[str, Meta(min_length=1, max_length=2048)] | msgspec.UnsetType = msgspec.UNSET
    description: Annotated[str, Meta(min_length=1, max_length=1000)] | msgspec.UnsetType | None = msgspec.UNSET
    events: list[str] | msgspec.UnsetType = msgspec.UNSET
    is_active: bool | msgspec.UnsetType = msgspec.UNSET
    secret: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType | None = msgspec.UNSET
    headers: dict[str, Any] | msgspec.UnsetType | None = msgspec.UNSET

    def __post_init__(self) -> None:
        if isinstance(self.url, str):
            self.url = validate_url(self.url)
