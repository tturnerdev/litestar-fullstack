"""Fax message schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from msgspec import Meta

from app.db.models._fax_enums import FaxDirection, FaxStatus
from app.lib.schema import CamelizedBaseStruct


class FaxMessage(CamelizedBaseStruct):
    """Full fax message representation."""

    id: UUID
    fax_number_id: UUID
    direction: FaxDirection
    remote_number: str
    remote_name: str | None = None
    page_count: int = 0
    status: FaxStatus = FaxStatus.RECEIVED
    file_path: str = ""
    file_size_bytes: int = 0
    error_message: str | None = None
    delivered_to_emails: list[str] | None = None
    received_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class FaxMessageCreate(CamelizedBaseStruct):
    """Schema for creating a fax message record."""

    fax_number_id: UUID
    direction: FaxDirection
    remote_number: Annotated[str, Meta(min_length=1, max_length=20)]
    remote_name: Annotated[str, Meta(min_length=1, max_length=255)] | None = None
    page_count: Annotated[int, Meta(ge=0)] = 0
    status: FaxStatus = FaxStatus.SENDING
    file_path: Annotated[str, Meta(max_length=2048)] = ""
    file_size_bytes: Annotated[int, Meta(ge=0)] = 0


class SendFax(CamelizedBaseStruct):
    """Schema for sending a fax."""

    fax_number_id: UUID
    destination_number: Annotated[str, Meta(min_length=1, max_length=20)]
    team_id: UUID
    subject: Annotated[str, Meta(min_length=1, max_length=255)] | None = None
    body: Annotated[str, Meta(min_length=1, max_length=50000)] | None = None
    media_url: Annotated[str, Meta(min_length=1, max_length=2048)] | None = None
