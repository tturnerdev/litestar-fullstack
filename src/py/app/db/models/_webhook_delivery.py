"""Webhook delivery record model."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.db.models._webhook import Webhook
    from app.db.models._webhook_endpoint import WebhookEndpoint


class WebhookDelivery(UUIDv7AuditBase):
    """A record of a single webhook delivery attempt."""

    __tablename__ = "webhook_delivery"
    __table_args__ = {"comment": "Records of individual webhook delivery attempts"}

    webhook_id: Mapped[UUID] = mapped_column(
        ForeignKey("webhook.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    endpoint_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("webhook_endpoint.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        default=None,
    )
    event: Mapped[str] = mapped_column(String(length=100), nullable=False)
    endpoint_url: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    """Snapshot of the endpoint URL at delivery time — used for retries."""
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True, default=None)
    """The full webhook payload — stored for retry attempts."""
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    response_time_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    # Retry fields
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    """Number of retry attempts made so far."""
    max_retries: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    """Maximum number of retries allowed for this delivery."""
    next_retry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None, index=True,
    )
    """When the next retry should be attempted. None means no retry pending."""

    # Relationships
    webhook: Mapped[Webhook] = relationship(
        foreign_keys=[webhook_id],
        lazy="noload",
        uselist=False,
    )
    endpoint: Mapped[WebhookEndpoint | None] = relationship(
        foreign_keys=[endpoint_id],
        lazy="noload",
        uselist=False,
    )

    def __repr__(self) -> str:
        return f"<WebhookDelivery id={self.id} webhook_id={self.webhook_id}>"
