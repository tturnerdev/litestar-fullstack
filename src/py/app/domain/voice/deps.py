"""Voice domain dependencies."""

from __future__ import annotations

from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.voice.services import (
    DoNotDisturbService,
    ExtensionService,
    ForwardingRuleService,
    PhoneNumberService,
    VoicemailBoxService,
    VoicemailMessageService,
)
from app.lib.deps import create_service_provider

provide_phone_numbers_service = create_service_provider(
    PhoneNumberService,
    error_messages={
        "duplicate_key": "Phone number already exists.",
        "integrity": "Phone number operation failed.",
    },
)

provide_extensions_service = create_service_provider(
    ExtensionService,
    error_messages={
        "duplicate_key": "Extension already exists.",
        "integrity": "Extension operation failed.",
    },
)

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
    error_messages={
        "duplicate_key": "Voicemail message already exists.",
        "integrity": "Voicemail message operation failed.",
    },
)

provide_forwarding_rules_service = create_service_provider(
    ForwardingRuleService,
    error_messages={
        "duplicate_key": "Forwarding rule already exists.",
        "integrity": "Forwarding rule operation failed.",
    },
)

provide_dnd_service = create_service_provider(
    DoNotDisturbService,
    load=[selectinload(m.DoNotDisturb.extension)],
    error_messages={
        "duplicate_key": "DND settings already exist for this extension.",
        "integrity": "DND operation failed.",
    },
)

__all__ = (
    "provide_dnd_service",
    "provide_extensions_service",
    "provide_forwarding_rules_service",
    "provide_phone_numbers_service",
    "provide_voicemail_boxes_service",
    "provide_voicemail_messages_service",
)
