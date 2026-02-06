"""Ticket attachment schemas."""

from uuid import UUID

from app.lib.schema import CamelizedBaseStruct


class TicketAttachment(CamelizedBaseStruct):
    id: UUID
    file_name: str
    file_size_bytes: int
    content_type: str
    is_inline: bool = False
    url: str = ""
