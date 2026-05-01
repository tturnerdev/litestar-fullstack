"""Voicemail domain dependencies."""

from __future__ import annotations

from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.voicemail.services import VoicemailBoxService, VoicemailMessageService
from app.lib.deps import create_service_provider

provide_voicemail_boxes_service = create_service_provider(
    VoicemailBoxService,
    load=[selectinload(m.VoicemailBox.extension)],
    error_messages={
        "duplicate_key": "Voicemail box already exists for this extension.",
        "integrity": "Voicemail box operation failed.",
    },
)

provide_voicemail_messages_service = create_service_provider(
    VoicemailMessageService,
    load=[selectinload(m.VoicemailMessage.voicemail_box)],
    error_messages={
        "duplicate_key": "Voicemail message already exists.",
        "integrity": "Voicemail message operation failed.",
    },
)

__all__ = (
    "provide_voicemail_boxes_service",
    "provide_voicemail_messages_service",
)
