"""Ticket message schemas."""

from datetime import datetime
from uuid import UUID

from app.domain.support.schemas._ticket import TicketUser
from app.domain.support.schemas._ticket_attachment import TicketAttachment
from app.lib.schema import CamelizedBaseStruct


class TicketMessage(CamelizedBaseStruct):
    id: UUID
    body_markdown: str
    body_html: str
    author: TicketUser | None = None
    is_internal_note: bool = False
    is_system_message: bool = False
    attachments: list[TicketAttachment] = []
    created_at: datetime | None = None


class TicketMessageCreate(CamelizedBaseStruct):
    body_markdown: str
    is_internal_note: bool = False
