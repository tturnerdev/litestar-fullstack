"""Fax email route schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct
from app.lib.validation import validate_email_format


class FaxEmailRoute(CamelizedBaseStruct):
    """Full fax email route representation."""

    id: UUID
    fax_number_id: UUID
    email_address: str
    is_active: bool = True
    notify_on_failure: bool = True
    created_at: datetime | None = None
    updated_at: datetime | None = None


class FaxEmailRouteCreate(CamelizedBaseStruct):
    """Schema for creating a fax email route."""

    email_address: Annotated[str, Meta(min_length=1, max_length=320)]
    is_active: bool = True
    notify_on_failure: bool = True

    def __post_init__(self) -> None:
        self.email_address = validate_email_format(self.email_address)


class FaxEmailRouteUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a fax email route."""

    email_address: Annotated[str, Meta(min_length=1, max_length=320)] | msgspec.UnsetType = msgspec.UNSET
    is_active: bool | msgspec.UnsetType = msgspec.UNSET
    notify_on_failure: bool | msgspec.UnsetType = msgspec.UNSET

    def __post_init__(self) -> None:
        if isinstance(self.email_address, str):
            self.email_address = validate_email_format(self.email_address)
