"""Connection schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct


class ConnectionList(CamelizedBaseStruct):
    """Connection list representation — credentials are never included."""

    id: UUID
    team_id: UUID
    name: str
    connection_type: str
    provider: str
    status: str
    is_enabled: bool = True
    host: str | None = None
    port: int | None = None
    auth_type: str | None = None
    description: str | None = None
    last_health_check: datetime | None = None
    last_error: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    managed_device_count: int = 0


class ConnectionDetail(CamelizedBaseStruct):
    """Full connection representation — credential keys shown, values masked."""

    id: UUID
    team_id: UUID
    name: str
    connection_type: str
    provider: str
    status: str
    auth_type: str
    is_enabled: bool = True
    host: str | None = None
    port: int | None = None
    description: str | None = None
    credential_fields: list[str] = []
    settings: dict | None = None
    last_health_check: datetime | None = None
    last_error: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    managed_device_count: int = 0


# Alias for convenience — used as the "standard" representation
Connection = ConnectionList


class ConnectionCreate(CamelizedBaseStruct):
    """Schema for creating a connection."""

    name: Annotated[str, Meta(min_length=1, max_length=255)]
    connection_type: Annotated[str, Meta(min_length=1, max_length=50)]
    provider: Annotated[str, Meta(min_length=1, max_length=100)]
    team_id: UUID | None = None
    host: Annotated[str, Meta(min_length=1, max_length=500)] | None = None
    port: Annotated[int, Meta(ge=1, le=65535)] | None = None
    auth_type: Annotated[str, Meta(min_length=1, max_length=50)] = "none"
    credentials: dict | None = None
    settings: dict | None = None
    description: Annotated[str, Meta(min_length=1, max_length=1000)] | None = None
    is_enabled: bool = True


class ConnectionUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a connection."""

    name: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    connection_type: Annotated[str, Meta(min_length=1, max_length=50)] | msgspec.UnsetType = msgspec.UNSET
    provider: Annotated[str, Meta(min_length=1, max_length=100)] | msgspec.UnsetType = msgspec.UNSET
    host: Annotated[str, Meta(min_length=1, max_length=500)] | msgspec.UnsetType | None = msgspec.UNSET
    port: Annotated[int, Meta(ge=1, le=65535)] | msgspec.UnsetType | None = msgspec.UNSET
    auth_type: Annotated[str, Meta(min_length=1, max_length=50)] | msgspec.UnsetType = msgspec.UNSET
    credentials: dict | msgspec.UnsetType | None = msgspec.UNSET
    settings: dict | msgspec.UnsetType | None = msgspec.UNSET
    description: Annotated[str, Meta(min_length=1, max_length=1000)] | msgspec.UnsetType | None = msgspec.UNSET
    is_enabled: bool | msgspec.UnsetType = msgspec.UNSET
