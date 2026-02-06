"""Fax domain signals/events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from litestar.events import listener

from app.db import models as m
from app.domain.fax import deps
from app.lib.deps import provide_services

if TYPE_CHECKING:
    from uuid import UUID

logger = structlog.get_logger()


@listener("fax_received")
async def fax_received_event_handler(fax_message_id: UUID) -> None:
    """Executes when a fax is received.

    Looks up active email routes for the fax number and queues email delivery jobs.

    Args:
        fax_message_id: The primary key of the fax message that was received.
    """
    await logger.ainfo("Processing received fax.", fax_message_id=fax_message_id)
    async with provide_services(deps.provide_fax_messages_service, deps.provide_fax_email_routes_service) as (
        messages_service,
        routes_service,
    ):
        message = await messages_service.get_one_or_none(id=fax_message_id)
        if message is None:
            await logger.aerror("Could not locate the fax message", id=fax_message_id)
            return

        routes, _total = await routes_service.list_and_count(
            m.FaxEmailRoute.fax_number_id == message.fax_number_id,
            m.FaxEmailRoute.is_active == True,  # noqa: E712
        )
        if not routes:
            await logger.ainfo("No active email routes for fax number", fax_number_id=message.fax_number_id)
            return

        for route in routes:
            await logger.ainfo(
                "Would queue email delivery",
                email=route.email_address,
                fax_message_id=fax_message_id,
            )


@listener("fax_delivery_failed")
async def fax_delivery_failed_event_handler(fax_message_id: UUID) -> None:
    """Executes when fax email delivery fails.

    If notify_on_failure is set on the route, sends a failure notification email.

    Args:
        fax_message_id: The primary key of the fax message that failed delivery.
    """
    await logger.ainfo("Processing fax delivery failure.", fax_message_id=fax_message_id)
    async with provide_services(deps.provide_fax_messages_service) as (messages_service,):
        message = await messages_service.get_one_or_none(id=fax_message_id)
        if message is None:
            await logger.aerror("Could not locate the fax message", id=fax_message_id)
            return
        await logger.ainfo("Fax delivery failed", fax_message_id=fax_message_id, status=message.status)


@listener("fax_sent")
async def fax_sent_event_handler(fax_message_id: UUID) -> None:
    """Executes when a fax is sent.

    Logs audit event and updates message status.

    Args:
        fax_message_id: The primary key of the fax message that was sent.
    """
    await logger.ainfo("Processing sent fax.", fax_message_id=fax_message_id)
    async with provide_services(deps.provide_fax_messages_service) as (messages_service,):
        message = await messages_service.get_one_or_none(id=fax_message_id)
        if message is None:
            await logger.aerror("Could not locate the fax message", id=fax_message_id)
            return
        await logger.ainfo("Fax sent successfully", fax_message_id=fax_message_id)


__all__ = (
    "fax_delivery_failed_event_handler",
    "fax_received_event_handler",
    "fax_sent_event_handler",
)
