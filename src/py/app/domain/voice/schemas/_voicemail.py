"""Voicemail schemas."""

import datetime as dt
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.db.models._voice_enums import GreetingType
from app.lib.schema import CamelizedBaseStruct
from app.lib.validation import validate_email_format


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
    created_at: dt.datetime | None = None
    updated_at: dt.datetime | None = None


class VoicemailSettingsUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Voicemail settings update properties."""

    is_enabled: bool | msgspec.UnsetType = msgspec.UNSET
    pin: Annotated[str, Meta(min_length=1, max_length=20)] | msgspec.UnsetType | None = msgspec.UNSET
    email_address: Annotated[str, Meta(min_length=1, max_length=320)] | msgspec.UnsetType | None = msgspec.UNSET
    greeting_type: GreetingType | msgspec.UnsetType = msgspec.UNSET
    max_message_length_seconds: Annotated[int, Meta(ge=1)] | msgspec.UnsetType = msgspec.UNSET
    email_notification: bool | msgspec.UnsetType = msgspec.UNSET
    email_attach_audio: bool | msgspec.UnsetType = msgspec.UNSET
    transcription_enabled: bool | msgspec.UnsetType = msgspec.UNSET
    auto_delete_days: Annotated[int, Meta(ge=1)] | msgspec.UnsetType | None = msgspec.UNSET

    def __post_init__(self) -> None:
        if isinstance(self.email_address, str):
            self.email_address = validate_email_format(self.email_address)


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
    received_at: dt.datetime | None = None
    created_at: dt.datetime | None = None
    updated_at: dt.datetime | None = None


class VoicemailMessageUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Voicemail message update properties."""

    is_read: bool | msgspec.UnsetType = msgspec.UNSET
