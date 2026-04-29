"""Notification preference model."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.db.models._user import User


DEFAULT_CATEGORIES: dict[str, bool] = {
    "teams": True,
    "devices": True,
    "voice": True,
    "fax": True,
    "support": True,
    "system": True,
}


class NotificationPreference(UUIDv7AuditBase):
    """User notification preferences."""

    __tablename__ = "notification_preference"
    __table_args__ = {"comment": "User notification delivery preferences"}

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("user_account.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )
    email_enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    categories: Mapped[dict[str, bool]] = mapped_column(
        JSONB,
        nullable=False,
        default=lambda: dict(DEFAULT_CATEGORIES),
    )

    user: Mapped[User] = relationship(
        back_populates="notification_preference",
        lazy="noload",
    )
