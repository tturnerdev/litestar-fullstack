"""Webhook model."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.db.models._user import User


class Webhook(UUIDv7AuditBase):
    """A webhook subscription for receiving event notifications via HTTP POST."""

    __tablename__ = "webhook"
    __table_args__ = {"comment": "Webhook subscriptions for event notifications"}

    name: Mapped[str] = mapped_column(String(length=100), nullable=False, index=True)
    url: Mapped[str] = mapped_column(String(length=500), nullable=False)
    secret: Mapped[str | None] = mapped_column(String(length=200), nullable=True, default=None)
    events: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    headers: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    last_triggered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    last_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    description: Mapped[str] = mapped_column(String(length=500), nullable=False, default="")
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("user_account.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Relationships
    user: Mapped[User] = relationship(
        foreign_keys="Webhook.user_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
