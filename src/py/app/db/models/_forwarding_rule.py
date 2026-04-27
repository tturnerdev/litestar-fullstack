from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._voice_enums import ForwardingDestinationType, ForwardingRuleType  # noqa: TC001

if TYPE_CHECKING:
    from app.db.models._extension import Extension


class ForwardingRule(UUIDv7AuditBase):
    """Call forwarding configuration."""

    __tablename__ = "forwarding_rule"
    __table_args__ = {"comment": "Call forwarding rules per extension"}

    extension_id: Mapped[UUID] = mapped_column(
        ForeignKey("extension.id", ondelete="cascade"), nullable=False, index=True
    )
    rule_type: Mapped[ForwardingRuleType] = mapped_column(
        String(length=20),
        nullable=False,
    )
    destination_type: Mapped[ForwardingDestinationType] = mapped_column(
        String(length=20),
        nullable=False,
    )
    destination_value: Mapped[str] = mapped_column(String(length=100), nullable=False)
    ring_timeout_seconds: Mapped[int | None] = mapped_column(nullable=True, default=None)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    priority: Mapped[int] = mapped_column(default=0, nullable=False)

    extension: Mapped[Extension] = relationship(
        back_populates="forwarding_rules",
        foreign_keys="ForwardingRule.extension_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
