"""Voicemail domain controllers."""

from app.domain.voicemail.controllers._voicemail_box import VoicemailBoxController
from app.domain.voicemail.controllers._voicemail_message import VoicemailMessageController

__all__ = (
    "VoicemailBoxController",
    "VoicemailMessageController",
)
