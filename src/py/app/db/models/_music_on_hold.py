"""Music on Hold model."""

from __future__ import annotations

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import Boolean, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column


class MusicOnHold(UUIDv7AuditBase):
    """A Music on Hold class defining audio files and playback settings."""

    __tablename__ = "music_on_hold"
    __table_args__ = {"comment": "Music on Hold classes with audio file lists and playback settings"}

    name: Mapped[str] = mapped_column(String(length=100), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(String(length=500), default="", nullable=False)
    category: Mapped[str] = mapped_column(String(length=50), default="custom", nullable=False, index=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    random_order: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    file_list: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
