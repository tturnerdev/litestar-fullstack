"""Support domain dependencies."""

from __future__ import annotations

from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.support.services import TicketAttachmentService, TicketMessageService, TicketService
from app.lib.deps import create_service_provider

provide_tickets_service = create_service_provider(
    TicketService,
    load=[m.Ticket.user, m.Ticket.assigned_to],
    error_messages={"duplicate_key": "This ticket already exists.", "integrity": "Ticket operation failed."},
)

provide_ticket_messages_service = create_service_provider(
    TicketMessageService,
    load=[selectinload(m.TicketMessage.author), selectinload(m.TicketMessage.attachments)],
    error_messages={"duplicate_key": "This message already exists.", "integrity": "Ticket message operation failed."},
)

provide_ticket_attachments_service = create_service_provider(
    TicketAttachmentService,
    error_messages={
        "duplicate_key": "This attachment already exists.",
        "integrity": "Ticket attachment operation failed.",
    },
)

__all__ = (
    "provide_ticket_attachments_service",
    "provide_ticket_messages_service",
    "provide_tickets_service",
)
