"""Fax message schemas."""

from datetime import datetime
from uuid import UUID

from app.db.models._fax_enums import FaxDirection, FaxStatus
from app.lib.schema import CamelizedBaseStruct


class FaxMessage(CamelizedBaseStruct):
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
    fax_number_id: UUID
    direction: FaxDirection
    remote_number: str
    remote_name: str | None = None
    page_count: int = 0
    status: FaxStatus = FaxStatus.SENDING
    file_path: str = ""
    file_size_bytes: int = 0


class SendFax(CamelizedBaseStruct):
    fax_number_id: UUID
    destination_number: str
    team_id: UUID
    subject: str | None = None
    body: str | None = None
    media_url: str | None = None
