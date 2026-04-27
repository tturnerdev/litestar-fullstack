"""Fax email route schemas."""

from datetime import datetime
from uuid import UUID

import msgspec

from app.lib.schema import CamelizedBaseStruct


class FaxEmailRoute(CamelizedBaseStruct):
    id: UUID
    fax_number_id: UUID
    email_address: str
    is_active: bool = True
    notify_on_failure: bool = True
    created_at: datetime | None = None
    updated_at: datetime | None = None


class FaxEmailRouteCreate(CamelizedBaseStruct):
    email_address: str
    is_active: bool = True
    notify_on_failure: bool = True


class FaxEmailRouteUpdate(CamelizedBaseStruct, omit_defaults=True):
    email_address: str | msgspec.UnsetType = msgspec.UNSET
    is_active: bool | msgspec.UnsetType = msgspec.UNSET
    notify_on_failure: bool | msgspec.UnsetType = msgspec.UNSET
