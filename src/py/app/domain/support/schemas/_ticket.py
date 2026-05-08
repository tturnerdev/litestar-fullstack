"""Ticket schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct


class TicketUser(CamelizedBaseStruct):
    """Embedded user info for ticket display."""

    id: UUID
    email: str
    name: str | None = None
    avatar_url: str | None = None


class Ticket(CamelizedBaseStruct):
    """Full support ticket representation."""

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
    """Schema for creating a support ticket."""

    subject: Annotated[str, Meta(min_length=1, max_length=255)]
    body_markdown: Annotated[str, Meta(min_length=1, max_length=50000)]
    priority: Annotated[str, Meta(min_length=1, max_length=50)] = "medium"
    category: Annotated[str, Meta(min_length=1, max_length=100)] | None = None
    team_id: UUID | None = None


class TicketUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a support ticket."""

    subject: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    status: Annotated[str, Meta(min_length=1, max_length=50)] | msgspec.UnsetType = msgspec.UNSET
    priority: Annotated[str, Meta(min_length=1, max_length=50)] | msgspec.UnsetType = msgspec.UNSET
    category: Annotated[str, Meta(min_length=1, max_length=100)] | msgspec.UnsetType | None = msgspec.UNSET
    assigned_to_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
