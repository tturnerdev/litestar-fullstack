"""Role-related schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct


class UserRoleAdd(CamelizedBaseStruct):
    """User role add ."""

    user_name: str


class UserRoleRevoke(CamelizedBaseStruct):
    """User role revoke ."""

    user_name: str


class Role(CamelizedBaseStruct):
    """Holds role details for a user.

    This is nested in the User Model for 'roles'
    """

    id: UUID
    slug: str
    name: str
    created_at: datetime
    updated_at: datetime


class RoleCreate(CamelizedBaseStruct):
    """Schema for creating a role."""

    name: Annotated[str, Meta(min_length=1, max_length=100)]


class RoleUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a role."""

    name: Annotated[str, Meta(min_length=1, max_length=100)] | msgspec.UnsetType | None = msgspec.UNSET
