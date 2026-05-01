"""Webhook delivery record model."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.db.models._webhook import Webhook


class WebhookDelivery(UUIDv7AuditBase):
    """A record of a single webhook delivery attempt."""

    __tablename__ = "webhook_delivery"
    __table_args__ = {"comment": "Records of individual webhook delivery attempts"}

    webhook_id: Mapped[UUID] = mapped_column(
        ForeignKey("webhook.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event: Mapped[str] = mapped_column(String(length=100), nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    response_time_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    # Relationships
    webhook: Mapped[Webhook] = relationship(
        foreign_keys=[webhook_id],
        lazy="noload",
        uselist=False,
    )
