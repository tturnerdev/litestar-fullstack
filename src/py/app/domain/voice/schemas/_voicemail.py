"""Voicemail schemas."""

from datetime import datetime
from uuid import UUID

import msgspec

from app.db.models._voice_enums import GreetingType
from app.lib.schema import CamelizedBaseStruct


class VoicemailSettings(CamelizedBaseStruct):
    """Voicemail box settings response."""

    id: UUID
    extension_id: UUID
    is_enabled: bool = True
    greeting_type: GreetingType = GreetingType.DEFAULT
    greeting_file_path: str | None = None
    max_message_length_seconds: int = 120
    email_address: str | None = None
    email_notification: bool = True
    email_attach_audio: bool = False
    transcription_enabled: bool = False
    auto_delete_days: int | None = None


class VoicemailSettingsUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Voicemail settings update properties."""

    is_enabled: bool | msgspec.UnsetType = msgspec.UNSET
    pin: str | msgspec.UnsetType | None = msgspec.UNSET
    email_address: str | msgspec.UnsetType | None = msgspec.UNSET
    greeting_type: GreetingType | msgspec.UnsetType = msgspec.UNSET
    max_message_length_seconds: int | msgspec.UnsetType = msgspec.UNSET
    email_notification: bool | msgspec.UnsetType = msgspec.UNSET
    email_attach_audio: bool | msgspec.UnsetType = msgspec.UNSET
    transcription_enabled: bool | msgspec.UnsetType = msgspec.UNSET
    auto_delete_days: int | msgspec.UnsetType | None = msgspec.UNSET


class VoicemailMessage(CamelizedBaseStruct):
    """Voicemail message response."""

    id: UUID
    voicemail_box_id: UUID
    caller_number: str
    caller_name: str | None = None
    duration_seconds: int = 0
    audio_file_path: str = ""
    transcription: str | None = None
    is_read: bool = False
    is_urgent: bool = False
    received_at: datetime | None = None


class VoicemailMessageUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Voicemail message update properties."""

    is_read: bool | msgspec.UnsetType = msgspec.UNSET
