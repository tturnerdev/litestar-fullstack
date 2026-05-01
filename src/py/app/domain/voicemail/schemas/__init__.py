"""Voicemail domain schemas."""

from app.domain.voicemail.schemas._voicemail_box import VoicemailBox, VoicemailBoxCreate, VoicemailBoxUpdate
from app.domain.voicemail.schemas._voicemail_message import (
    VoicemailMessage,
    VoicemailMessageCreate,
    VoicemailMessageUpdate,
    VoicemailReadToggle,
    VoicemailUnreadCount,
)
from app.lib.schema import Message

__all__ = (
    "Message",
    "VoicemailBox",
    "VoicemailBoxCreate",
    "VoicemailBoxUpdate",
    "VoicemailMessage",
    "VoicemailMessageCreate",
    "VoicemailMessageUpdate",
    "VoicemailReadToggle",
    "VoicemailUnreadCount",
)
