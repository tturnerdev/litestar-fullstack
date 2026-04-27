"""Support domain controllers."""

from app.domain.support.controllers._ticket import TicketController
from app.domain.support.controllers._ticket_attachment import TicketAttachmentController
from app.domain.support.controllers._ticket_message import TicketMessageController

__all__ = (
    "TicketAttachmentController",
    "TicketController",
    "TicketMessageController",
)
