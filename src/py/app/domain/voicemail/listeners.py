"""Voicemail domain signals/events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from litestar.events import listener

from app.domain.voicemail import deps
from app.lib.deps import provide_services

if TYPE_CHECKING:
    from uuid import UUID

logger = structlog.get_logger()


@listener("voicemail_box_created")
async def voicemail_box_created_event_handler(voicemail_box_id: UUID) -> None:
    """Executes when a new voicemail box is created.

    Args:
        voicemail_box_id: The primary key of the voicemail box that was created.
    """
    await logger.ainfo("Voicemail box created.", voicemail_box_id=voicemail_box_id)
    async with provide_services(deps.provide_voicemail_boxes_service) as (service,):
        obj = await service.get_one_or_none(id=voicemail_box_id)
        if obj is None:
            await logger.aerror("Could not locate the voicemail box", id=voicemail_box_id)
        else:
            await logger.ainfo(
                "Voicemail box created",
                voicemail_box_id=str(obj.id),
                extension_id=str(obj.extension_id),
            )


@listener("voicemail_message_received")
async def voicemail_message_received_event_handler(message_id: UUID) -> None:
    """Executes when a new voicemail message is received.

    Could trigger email notification delivery.

    Args:
        message_id: The primary key of the voicemail message that was received.
    """
    await logger.ainfo("New voicemail message received.", message_id=message_id)
    async with provide_services(deps.provide_voicemail_messages_service) as (service,):
        message = await service.get_one_or_none(id=message_id)
        if message is None:
            await logger.aerror("Could not locate the voicemail message", id=message_id)
            return
        await logger.ainfo(
            "Voicemail message received",
            message_id=str(message.id),
            voicemail_box_id=str(message.voicemail_box_id),
            caller_number=message.caller_number,
        )


__all__ = (
    "voicemail_box_created_event_handler",
    "voicemail_message_received_event_handler",
)
