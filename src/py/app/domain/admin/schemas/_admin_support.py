"""Admin support overview schemas."""

from datetime import datetime
from uuid import UUID

from app.lib.schema import CamelizedBaseStruct


class AdminSupportStats(CamelizedBaseStruct):
    """Aggregate support ticket statistics for admin overview."""

    total: int
    open: int
    in_progress: int
    waiting_on_customer: int
    waiting_on_support: int
    resolved: int
    closed: int
    by_priority: dict[str, int]
    by_category: dict[str, int]


class AdminTicketSummary(CamelizedBaseStruct, kw_only=True):
    """Summary ticket info for admin lists."""

    id: UUID
    ticket_number: str
    subject: str
    status: str
    priority: str
    category: str | None = None
    is_read_by_agent: bool
    creator_email: str | None = None
    assigned_to_email: str | None = None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None = None
