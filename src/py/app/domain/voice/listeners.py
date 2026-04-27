"""Voice domain signals/events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from litestar.events import listener

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
