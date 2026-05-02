"""Voice domain signals/events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from litestar.events import listener

from app.domain.notifications import deps as notification_deps
from app.domain.voice import deps
from app.lib.deps import provide_services

if TYPE_CHECKING:
    from uuid import UUID

logger = structlog.get_logger()


@listener("voicemail_received")
async def voicemail_received_event_handler(voicemail_box_id: UUID, message_id: UUID) -> None:
    """Executes when a new voicemail message is received."""
    await logger.ainfo(
        "New voicemail received.",
        voicemail_box_id=voicemail_box_id,
        message_id=message_id,
    )
    async with provide_services(
        deps.provide_voicemail_boxes_service, notification_deps.provide_notifications_service
    ) as (voicemail_service, notification_service):
        voicemail_box = await voicemail_service.get_one_or_none(id=voicemail_box_id)
        if voicemail_box is None:
            await logger.aerror("Could not locate voicemail box for notification", id=voicemail_box_id)
        else:
            try:
                await notification_service.notify(
                    user_id=voicemail_box.extension.user_id,
                    title="New Voicemail",
                    message="You have a new voicemail message.",
                    category="voice",
                    action_url=f"/voice/extensions/{voicemail_box.extension_id}/voicemail",
                )
            except Exception:
                await logger.aerror(
                    "Failed to create notification for voicemail_received", voicemail_box_id=voicemail_box_id
                )


@listener("forwarding_rules_changed")
async def forwarding_rules_changed_event_handler(extension_id: UUID) -> None:
    """Executes when forwarding rules are changed for an extension."""
    await logger.ainfo(
        "Forwarding rules changed.",
        extension_id=extension_id,
    )


@listener("dnd_toggled")
async def dnd_toggled_event_handler(extension_id: UUID, is_enabled: bool) -> None:
    """Executes when DND is toggled for an extension."""
    await logger.ainfo(
        "DND toggled.",
        extension_id=extension_id,
        is_enabled=is_enabled,
    )


__all__ = (
    "dnd_toggled_event_handler",
    "forwarding_rules_changed_event_handler",
    "voicemail_received_event_handler",
)
