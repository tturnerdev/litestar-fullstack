"""Support domain signals/events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from litestar.events import listener

from app.domain.support import deps
from app.lib.deps import provide_services

if TYPE_CHECKING:
    from uuid import UUID

    from app.lib.email import AppEmailService

logger = structlog.get_logger()


@listener("ticket_created")
async def ticket_created_event_handler(ticket_id: UUID) -> None:
    """Executes when a new ticket is created.

    Args:
        ticket_id: The primary key of the ticket that was created.
    """
    await logger.ainfo("Running post ticket creation flow.")
    async with provide_services(deps.provide_tickets_service) as (service,):
        obj = await service.get_one_or_none(id=ticket_id)
        if obj is None:
            await logger.aerror("Could not locate the specified ticket", id=ticket_id)
        else:
            await logger.ainfo("Ticket created", ticket_number=obj.ticket_number, subject=obj.subject)


@listener("ticket_message_created")
async def ticket_message_created_event_handler(ticket_id: UUID, message_id: UUID) -> None:
    """Executes when a new message is added to a ticket.

    Args:
        ticket_id: The ticket ID.
        message_id: The message ID.
    """
    await logger.ainfo("Running post ticket message creation flow.", ticket_id=ticket_id, message_id=message_id)


@listener("ticket_status_changed")
async def ticket_status_changed_event_handler(ticket_id: UUID, old_status: str, new_status: str) -> None:
    """Executes when a ticket status changes.

    Args:
        ticket_id: The ticket ID.
        old_status: The previous status.
        new_status: The new status.
    """
    await logger.ainfo(
        "Ticket status changed.",
        ticket_id=ticket_id,
        old_status=old_status,
        new_status=new_status,
    )


@listener("ticket_assigned")
async def ticket_assigned_event_handler(ticket_id: UUID, assigned_to_id: UUID) -> None:
    """Executes when a ticket is assigned to an agent.

    Args:
        ticket_id: The ticket ID.
        assigned_to_id: The assigned agent's user ID.
    """
    await logger.ainfo("Ticket assigned.", ticket_id=ticket_id, assigned_to_id=assigned_to_id)


__all__ = (
    "ticket_assigned_event_handler",
    "ticket_created_event_handler",
    "ticket_message_created_event_handler",
    "ticket_status_changed_event_handler",
)
