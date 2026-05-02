"""Webhook endpoint model for storing registered webhook subscriptions."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column


class WebhookEndpoint(UUIDv7AuditBase):
    """A registered webhook endpoint that receives event notifications.

    Teams can register URLs to receive HTTP POST callbacks when
    specific events occur in the system.
    """

    __tablename__ = "webhook_endpoint"
    __table_args__ = {"comment": "Registered webhook endpoints for event notifications"}

    team_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("team.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    """Team that owns this webhook (null for system-level webhooks)."""

    url: Mapped[str] = mapped_column(Text, nullable=False)
    """The URL to deliver webhook payloads to."""

    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    """Optional description of this webhook endpoint."""

    secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    """Shared secret for HMAC signature verification."""

    events: Mapped[list[str]] = mapped_column(
        ARRAY(String(100)),
        nullable=False,
        default=list,
    )
    """List of event types this endpoint subscribes to (e.g., ['user.login', 'user.created'])."""

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    """Whether this webhook endpoint is currently active."""

    headers: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    """Custom headers to include in webhook deliveries."""
