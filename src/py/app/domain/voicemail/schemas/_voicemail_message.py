"""Voicemail message schemas."""

from datetime import datetime
from uuid import UUID

import msgspec

from app.lib.schema import CamelizedBaseStruct


class VoicemailMessage(CamelizedBaseStruct):
    """Full voicemail message representation."""

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
    created_at: datetime | None = None
    updated_at: datetime | None = None


class VoicemailMessageCreate(CamelizedBaseStruct):
    """Schema for creating a voicemail message."""

    voicemail_box_id: UUID
    caller_number: str
    caller_name: str | None = None
    duration_seconds: int = 0
    audio_file_path: str = ""
    transcription: str | None = None
    is_urgent: bool = False
    received_at: datetime | None = None


class VoicemailMessageUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a voicemail message."""

    is_read: bool | msgspec.UnsetType = msgspec.UNSET
    is_urgent: bool | msgspec.UnsetType = msgspec.UNSET
    transcription: str | msgspec.UnsetType | None = msgspec.UNSET


class VoicemailReadToggle(CamelizedBaseStruct):
    """Schema for toggling read status."""

    is_read: bool


class VoicemailUnreadCount(CamelizedBaseStruct):
    """Unread message count response."""

    voicemail_box_id: UUID
    unread_count: int
