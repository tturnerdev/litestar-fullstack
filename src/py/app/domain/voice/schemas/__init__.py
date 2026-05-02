"""Voice domain schemas."""

from app.domain.voice.schemas._dnd import DndSettings, DndSettingsUpdate, DndToggleResponse
from app.domain.voice.schemas._extension import (
    Extension,
    ExtensionCreate,
    ExtensionDeviceSummary,
    ExtensionSyncResult,
    ExtensionUpdate,
)
from app.domain.voice.schemas._forwarding import ForwardingRule, ForwardingRuleCreate, ForwardingRuleUpdate
from app.domain.voice.schemas._phone_number import PhoneNumber, PhoneNumberCreate, PhoneNumberUpdate
from app.domain.voice.schemas._voicemail import (
    VoicemailMessage,
    VoicemailMessageUpdate,
    VoicemailSettings,
    VoicemailSettingsUpdate,
)

__all__ = (
    "DndSettings",
    "DndSettingsUpdate",
    "DndToggleResponse",
    "Extension",
    "ExtensionCreate",
    "ExtensionDeviceSummary",
    "ExtensionSyncResult",
    "ExtensionUpdate",
    "ForwardingRule",
    "ForwardingRuleCreate",
    "ForwardingRuleUpdate",
    "PhoneNumber",
    "PhoneNumberCreate",
    "PhoneNumberUpdate",
    "VoicemailMessage",
    "VoicemailMessageUpdate",
    "VoicemailSettings",
    "VoicemailSettingsUpdate",
)
