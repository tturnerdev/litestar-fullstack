"""Support domain schemas."""

from app.domain.support.schemas._ticket import Ticket, TicketCreate, TicketUpdate, TicketUser
from app.domain.support.schemas._ticket_attachment import TicketAttachment
from app.domain.support.schemas._ticket_message import TicketMessage, TicketMessageCreate
from app.lib.schema import Message

__all__ = (
    "Message",
    "Ticket",
    "TicketAttachment",
    "TicketCreate",
    "TicketMessage",
    "TicketMessageCreate",
    "TicketUpdate",
    "TicketUser",
)
