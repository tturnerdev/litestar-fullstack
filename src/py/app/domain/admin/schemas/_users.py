"""Admin user schemas."""

from datetime import date, datetime
from typing import Annotated
from uuid import UUID

from msgspec import UNSET, Meta, UnsetType

from app.domain.accounts.schemas import OauthAccount, UserRole, UserTeam
from app.lib.schema import CamelizedBaseStruct


class AdminUserSummary(CamelizedBaseStruct, kw_only=True):
    """Summary user info for admin lists."""

    id: UUID
    email: str
    created_at: datetime
    name: str | None = None
    username: str | None = None
    is_active: bool = True
    is_superuser: bool = False
    is_verified: bool = False
    login_count: int = 0


class AdminUserDetail(CamelizedBaseStruct, kw_only=True):
    """Detailed user info for admin view."""

    id: UUID
    email: str
    created_at: datetime
    updated_at: datetime
    name: str | None = None
    username: str | None = None
    phone: str | None = None
    is_active: bool = True
    is_superuser: bool = False
    is_verified: bool = False
    verified_at: date | None = None
    joined_at: date | None = None
    login_count: int = 0
    is_two_factor_enabled: bool = False
    has_password: bool = True
    roles: list[UserRole] = []
    teams: list[UserTeam] = []
    oauth_accounts: list[OauthAccount] = []


class AdminUserUpdate(CamelizedBaseStruct, gc=False, omit_defaults=True):
    """Update payload for admin user management."""

    name: Annotated[str, Meta(max_length=255)] | UnsetType | None = UNSET
    username: Annotated[str, Meta(max_length=30)] | UnsetType | None = UNSET
    phone: Annotated[str, Meta(max_length=20)] | UnsetType | None = UNSET
    is_active: bool | UnsetType = UNSET
    is_superuser: bool | UnsetType = UNSET
    is_verified: bool | UnsetType = UNSET
