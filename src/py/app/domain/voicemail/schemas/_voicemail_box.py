"""Voicemail box schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

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
    pin: Annotated[str, Meta(min_length=4, max_length=8)] | None = None
    email_address: Annotated[str, Meta(min_length=1, max_length=255)] | None = None
    email_notification: bool = True
    email_attach_audio: bool = False
    transcription_enabled: bool = False
    greeting_type: GreetingType = GreetingType.DEFAULT
    greeting_file_path: Annotated[str, Meta(min_length=1, max_length=500)] | None = None
    max_message_length_seconds: Annotated[int, Meta(ge=10, le=600)] = 120
    auto_delete_days: Annotated[int, Meta(ge=1, le=365)] | None = None


class VoicemailBoxUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a voicemail box."""

    is_enabled: bool | msgspec.UnsetType = msgspec.UNSET
    pin: Annotated[str, Meta(min_length=4, max_length=8)] | msgspec.UnsetType | None = msgspec.UNSET
    email_address: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType | None = msgspec.UNSET
    email_notification: bool | msgspec.UnsetType = msgspec.UNSET
    email_attach_audio: bool | msgspec.UnsetType = msgspec.UNSET
    transcription_enabled: bool | msgspec.UnsetType = msgspec.UNSET
    greeting_type: GreetingType | msgspec.UnsetType = msgspec.UNSET
    greeting_file_path: Annotated[str, Meta(min_length=1, max_length=500)] | msgspec.UnsetType | None = msgspec.UNSET
    max_message_length_seconds: Annotated[int, Meta(ge=10, le=600)] | msgspec.UnsetType = msgspec.UNSET
    auto_delete_days: Annotated[int, Meta(ge=1, le=365)] | msgspec.UnsetType | None = msgspec.UNSET
