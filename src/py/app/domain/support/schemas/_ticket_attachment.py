"""Ticket attachment schemas."""

import datetime as dt
from uuid import UUID

from app.lib.schema import CamelizedBaseStruct


class TicketAttachment(CamelizedBaseStruct):
    id: UUID
    file_name: str
    file_size_bytes: int
    content_type: str
    is_inline: bool = False
    url: str = ""
    created_at: dt.datetime | None = None
    updated_at: dt.datetime | None = None
