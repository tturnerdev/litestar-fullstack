"""Admin fax overview schemas."""

from datetime import datetime
from uuid import UUID

from app.lib.schema import CamelizedBaseStruct


class AdminFaxStats(CamelizedBaseStruct):
    """Aggregate fax statistics for admin overview."""

    total_numbers: int
    active_numbers: int
    total_messages: int
    messages_today: int
    inbound_today: int
    outbound_today: int
    failed_today: int


class AdminFaxNumberSummary(CamelizedBaseStruct, kw_only=True):
    """Summary fax number info for admin lists."""

    id: UUID
    number: str
    label: str | None = None
    is_active: bool
    owner_email: str | None = None
    team_name: str | None = None
    created_at: datetime


class AdminFaxMessageSummary(CamelizedBaseStruct, kw_only=True):
    """Summary fax message info for admin lists."""

    id: UUID
    fax_number: str
    direction: str
    remote_number: str
    remote_name: str | None = None
    page_count: int
    status: str
    error_message: str | None = None
    received_at: datetime
    created_at: datetime
