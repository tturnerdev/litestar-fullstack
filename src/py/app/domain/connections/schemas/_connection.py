"""Connection schemas."""

from datetime import datetime
from uuid import UUID

import msgspec

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


# Alias for convenience — used as the "standard" representation
Connection = ConnectionList


class ConnectionCreate(CamelizedBaseStruct):
    """Schema for creating a connection."""

    name: str
    connection_type: str
    provider: str
    team_id: UUID | None = None
    host: str | None = None
    port: int | None = None
    auth_type: str = "none"
    credentials: dict | None = None
    settings: dict | None = None
    description: str | None = None
    is_enabled: bool = True


class ConnectionUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a connection."""

    name: str | msgspec.UnsetType = msgspec.UNSET
    connection_type: str | msgspec.UnsetType = msgspec.UNSET
    provider: str | msgspec.UnsetType = msgspec.UNSET
    host: str | msgspec.UnsetType | None = msgspec.UNSET
    port: int | msgspec.UnsetType | None = msgspec.UNSET
    auth_type: str | msgspec.UnsetType = msgspec.UNSET
    credentials: dict | msgspec.UnsetType | None = msgspec.UNSET
    settings: dict | msgspec.UnsetType | None = msgspec.UNSET
    description: str | msgspec.UnsetType | None = msgspec.UNSET
    is_enabled: bool | msgspec.UnsetType = msgspec.UNSET
