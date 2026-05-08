"""Webhook schemas."""

from datetime import datetime
from uuid import UUID

import msgspec

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

    name: str
    url: str
    secret: str | None = None
    events: list[str] = []
    is_active: bool = True
    headers: dict[str, str] = {}
    description: str = ""


class WebhookUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a webhook."""

    name: str | msgspec.UnsetType = msgspec.UNSET
    url: str | msgspec.UnsetType = msgspec.UNSET
    secret: str | msgspec.UnsetType | None = msgspec.UNSET
    events: list[str] | msgspec.UnsetType = msgspec.UNSET
    is_active: bool | msgspec.UnsetType = msgspec.UNSET
    headers: dict[str, str] | msgspec.UnsetType = msgspec.UNSET
    description: str | msgspec.UnsetType = msgspec.UNSET


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
