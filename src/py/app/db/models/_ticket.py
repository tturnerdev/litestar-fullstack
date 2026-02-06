from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._ticket_status import TicketCategory, TicketPriority, TicketStatus

if TYPE_CHECKING:
    from app.db.models._ticket_attachment import TicketAttachment
    from app.db.models._ticket_message import TicketMessage
    from app.db.models._user import User


class Ticket(UUIDv7AuditBase):
    """A support ticket."""

    __tablename__ = "ticket"
    __table_args__ = {"comment": "Support tickets for helpdesk system"}

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("user_account.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    assigned_to_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("user_account.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    team_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("team.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    ticket_number: Mapped[str] = mapped_column(
        String(length=20),
        unique=True,
        nullable=False,
        index=True,
    )
    subject: Mapped[str] = mapped_column(String(length=255), nullable=False)
    status: Mapped[str] = mapped_column(
        String(length=50),
        default=TicketStatus.OPEN,
        nullable=False,
        index=True,
    )
    priority: Mapped[str] = mapped_column(
        String(length=50),
        default=TicketPriority.MEDIUM,
        nullable=False,
        index=True,
    )
    category: Mapped[str | None] = mapped_column(
        String(length=50),
        nullable=True,
        default=None,
    )
    is_read_by_user: Mapped[bool] = mapped_column(default=True, nullable=False)
    is_read_by_agent: Mapped[bool] = mapped_column(default=False, nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(nullable=True, default=None)
    resolved_at: Mapped[datetime | None] = mapped_column(nullable=True, default=None)

    # Relationships
    user: Mapped[User] = relationship(
        foreign_keys=[user_id],
        lazy="joined",
        innerjoin=True,
        uselist=False,
    )
    assigned_to: Mapped[User | None] = relationship(
        foreign_keys=[assigned_to_id],
        lazy="joined",
        uselist=False,
    )
    messages: Mapped[list[TicketMessage]] = relationship(
        back_populates="ticket",
        cascade="all, delete",
        passive_deletes=True,
        lazy="noload",
    )
    attachments: Mapped[list[TicketAttachment]] = relationship(
        back_populates="ticket",
        cascade="all, delete",
        passive_deletes=True,
        lazy="noload",
        foreign_keys="TicketAttachment.ticket_id",
    )
