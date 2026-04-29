"""Notification model for in-app user notifications."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.db.models._user import User


class Notification(UUIDv7AuditBase):
    """In-app notification for a user.

    Tracks events, actions, and alerts that users should be aware of.
    """

    __tablename__ = "notification"
    __table_args__ = {"comment": "In-app notifications for users"}

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("user_account.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    """ID of the user who should receive the notification."""

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    """Short title for the notification."""

    message: Mapped[str] = mapped_column(String(1000), nullable=False)
    """Notification message body."""

    category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    """Category of notification (ticket, team, device, system, voice, fax)."""

    is_read: Mapped[bool] = mapped_column(default=False, nullable=False, index=True)
    """Whether the notification has been read."""

    action_url: Mapped[str | None] = mapped_column(String(500), nullable=True, default=None)
    """Optional URL to navigate to when the notification is clicked."""

    metadata_: Mapped[dict[str, Any] | None] = mapped_column(
        "metadata",
        JSONB,
        nullable=True,
        default=None,
    )
    """Additional structured data about the notification."""

    user: Mapped[User] = relationship(lazy="noload", foreign_keys=[user_id])
