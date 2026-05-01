"""Voicemail box schemas."""

from datetime import datetime
from uuid import UUID

import msgspec

from app.db.models._voice_enums import GreetingType
from app.lib.schema import CamelizedBaseStruct


class VoicemailBox(CamelizedBaseStruct):
    """Full voicemail box representation."""

    id: UUID
    extension_id: UUID
    is_enabled: bool = True
    pin: str | None = None
    email_address: str | None = None
    email_notification: bool = True
    email_attach_audio: bool = False
    transcription_enabled: bool = False
    greeting_type: GreetingType = GreetingType.DEFAULT
    greeting_file_path: str | None = None
    max_message_length_seconds: int = 120
    auto_delete_days: int | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class VoicemailBoxCreate(CamelizedBaseStruct):
    """Schema for creating a voicemail box."""

    extension_id: UUID
    is_enabled: bool = True
    pin: str | None = None
    email_address: str | None = None
    email_notification: bool = True
    email_attach_audio: bool = False
    transcription_enabled: bool = False
    greeting_type: GreetingType = GreetingType.DEFAULT
    greeting_file_path: str | None = None
    max_message_length_seconds: int = 120
    auto_delete_days: int | None = None


class VoicemailBoxUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a voicemail box."""

    is_enabled: bool | msgspec.UnsetType = msgspec.UNSET
    pin: str | msgspec.UnsetType | None = msgspec.UNSET
    email_address: str | msgspec.UnsetType | None = msgspec.UNSET
    email_notification: bool | msgspec.UnsetType = msgspec.UNSET
    email_attach_audio: bool | msgspec.UnsetType = msgspec.UNSET
    transcription_enabled: bool | msgspec.UnsetType = msgspec.UNSET
    greeting_type: GreetingType | msgspec.UnsetType = msgspec.UNSET
    greeting_file_path: str | msgspec.UnsetType | None = msgspec.UNSET
    max_message_length_seconds: int | msgspec.UnsetType = msgspec.UNSET
    auto_delete_days: int | msgspec.UnsetType | None = msgspec.UNSET
