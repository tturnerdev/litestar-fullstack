from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from advanced_alchemy.types import DateTimeUTC
from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.db.models._voicemail_box import VoicemailBox


class VoicemailMessage(UUIDv7AuditBase):
    """Individual voicemail messages."""

    __tablename__ = "voicemail_message"
    __table_args__ = {"comment": "Individual voicemail messages"}

    voicemail_box_id: Mapped[UUID] = mapped_column(
        ForeignKey("voicemail_box.id", ondelete="cascade"), nullable=False, index=True
    )
    caller_number: Mapped[str] = mapped_column(String(length=20), nullable=False)
    caller_name: Mapped[str | None] = mapped_column(String(length=100), nullable=True, default=None)
    duration_seconds: Mapped[int] = mapped_column(nullable=False)
    audio_file_path: Mapped[str] = mapped_column(String(length=500), nullable=False)
    transcription: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    is_read: Mapped[bool] = mapped_column(default=False, nullable=False)
    is_urgent: Mapped[bool] = mapped_column(default=False, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTimeUTC(timezone=True), nullable=False)

    voicemail_box: Mapped[VoicemailBox] = relationship(
        back_populates="messages",
        foreign_keys="VoicemailMessage.voicemail_box_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
