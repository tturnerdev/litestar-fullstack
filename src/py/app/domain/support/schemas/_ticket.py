"""Ticket schemas."""

from datetime import datetime
from uuid import UUID

import msgspec

from app.lib.schema import CamelizedBaseStruct


class TicketUser(CamelizedBaseStruct):
    """Embedded user info for ticket display."""

    id: UUID
    email: str
    name: str | None = None
    avatar_url: str | None = None


class Ticket(CamelizedBaseStruct):
    id: UUID
    ticket_number: str
    subject: str
    status: str
    priority: str
    category: str | None = None
    is_read_by_user: bool = True
    is_read_by_agent: bool = False
    user: TicketUser | None = None
    assigned_to: TicketUser | None = None
    message_count: int = 0
    latest_message_preview: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    closed_at: datetime | None = None
    resolved_at: datetime | None = None


class TicketCreate(CamelizedBaseStruct):
    subject: str
    body_markdown: str
    priority: str = "medium"
    category: str | None = None
    team_id: UUID | None = None


class TicketUpdate(CamelizedBaseStruct, omit_defaults=True):
    subject: str | msgspec.UnsetType = msgspec.UNSET
    status: str | msgspec.UnsetType = msgspec.UNSET
    priority: str | msgspec.UnsetType = msgspec.UNSET
    category: str | msgspec.UnsetType | None = msgspec.UNSET
    assigned_to_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
