from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from advanced_alchemy.types import EncryptedString
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._voice_enums import GreetingType
from app.lib.settings import get_settings

if TYPE_CHECKING:
    from app.db.models._extension import Extension
    from app.db.models._voicemail_message import VoicemailMessage

settings = get_settings()


class VoicemailBox(UUIDv7AuditBase):
    """Voicemail configuration for an extension."""

    __tablename__ = "voicemail_box"
    __table_args__ = {"comment": "Voicemail box configuration per extension"}

    extension_id: Mapped[UUID] = mapped_column(
        ForeignKey("extension.id", ondelete="cascade"), nullable=False, unique=True
    )
    is_enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    pin: Mapped[str | None] = mapped_column(
        EncryptedString(key=settings.app.SECRET_KEY),
        nullable=True,
        default=None,
    )
    greeting_type: Mapped[GreetingType] = mapped_column(
        String(length=20),
        default=GreetingType.DEFAULT,
        nullable=False,
    )
    greeting_file_path: Mapped[str | None] = mapped_column(String(length=500), nullable=True, default=None)
    max_message_length_seconds: Mapped[int] = mapped_column(default=120, nullable=False)
    email_address: Mapped[str | None] = mapped_column(String(length=255), nullable=True, default=None)
    email_notification: Mapped[bool] = mapped_column(default=True, nullable=False)
    email_attach_audio: Mapped[bool] = mapped_column(default=False, nullable=False)
    transcription_enabled: Mapped[bool] = mapped_column(default=False, nullable=False)
    auto_delete_days: Mapped[int | None] = mapped_column(nullable=True, default=None)

    extension: Mapped[Extension] = relationship(
        back_populates="voicemail_box",
        foreign_keys="VoicemailBox.extension_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
    messages: Mapped[list[VoicemailMessage]] = relationship(
        back_populates="voicemail_box",
        lazy="noload",
        uselist=True,
        cascade="all, delete",
    )
