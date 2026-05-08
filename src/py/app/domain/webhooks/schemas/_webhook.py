"""Webhook schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct


class WebhookList(CamelizedBaseStruct):
    """Webhook list representation (summary view)."""

    id: UUID
    name: str
    url: str
    events: list[str]
    is_active: bool
    last_triggered_at: datetime | None = None
    last_status_code: int | None = None
    failure_count: int = 0
    validation_status: str | None = None
    last_validated_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class WebhookDetail(CamelizedBaseStruct):
    """Full webhook representation (detail view)."""

    id: UUID
    name: str
    url: str
    events: list[str]
    is_active: bool
    secret: str | None = None
    headers: dict[str, str] = {}
    description: str = ""
    last_triggered_at: datetime | None = None
    last_status_code: int | None = None
    failure_count: int = 0
    validation_status: str | None = None
    last_validated_at: datetime | None = None
    user_id: UUID | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class WebhookCreate(CamelizedBaseStruct):
    """Schema for creating a webhook."""

    name: Annotated[str, Meta(min_length=1, max_length=100)]
    url: Annotated[str, Meta(min_length=1, max_length=500)]
    secret: Annotated[str, Meta(min_length=1, max_length=200)] | None = None
    events: list[str] = []
    is_active: bool = True
    headers: dict[str, str] = {}
    description: Annotated[str, Meta(max_length=500)] = ""


class WebhookUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a webhook."""

    name: Annotated[str, Meta(min_length=1, max_length=100)] | msgspec.UnsetType = msgspec.UNSET
    url: Annotated[str, Meta(min_length=1, max_length=500)] | msgspec.UnsetType = msgspec.UNSET
    secret: Annotated[str, Meta(min_length=1, max_length=200)] | msgspec.UnsetType | None = msgspec.UNSET
    events: list[str] | msgspec.UnsetType = msgspec.UNSET
    is_active: bool | msgspec.UnsetType = msgspec.UNSET
    headers: dict[str, str] | msgspec.UnsetType = msgspec.UNSET
    description: Annotated[str, Meta(min_length=1, max_length=500)] | msgspec.UnsetType = msgspec.UNSET


class WebhookTestResult(CamelizedBaseStruct):
    """Result of testing a webhook delivery."""

    success: bool
    status_code: int | None = None
    response_time_ms: int = 0
    error: str | None = None


class WebhookDeliveryList(CamelizedBaseStruct):
    """Webhook delivery record (list view)."""

    id: UUID
    webhook_id: UUID
    event: str
    endpoint_id: UUID | None = None
    endpoint_url: str | None = None
    status_code: int | None = None
    response_time_ms: int = 0
    success: bool = False
    error: str | None = None
    retry_count: int = 0
    max_retries: int = 5
    next_retry_at: datetime | None = None
    created_at: datetime | None = None


class WebhookDeliveryDetail(CamelizedBaseStruct):
    """Full webhook delivery record (detail view)."""

    id: UUID
    webhook_id: UUID
    event: str
    endpoint_id: UUID | None = None
    endpoint_url: str | None = None
    payload: dict[str, object] | None = None
    status_code: int | None = None
    response_time_ms: int = 0
    success: bool = False
    error: str | None = None
    retry_count: int = 0
    max_retries: int = 5
    next_retry_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
