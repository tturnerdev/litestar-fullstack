from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.db.models._ticket import Ticket
    from app.db.models._ticket_attachment import TicketAttachment
    from app.db.models._user import User


class TicketMessage(UUIDv7AuditBase):
    """A message/reply within a ticket thread."""

    __tablename__ = "ticket_message"
    __table_args__ = {"comment": "Messages within support ticket threads"}

    ticket_id: Mapped[UUID] = mapped_column(
        ForeignKey("ticket.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    author_id: Mapped[UUID] = mapped_column(
        ForeignKey("user_account.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    body_markdown: Mapped[str] = mapped_column(Text, nullable=False)
    body_html: Mapped[str] = mapped_column(Text, nullable=False)
    is_internal_note: Mapped[bool] = mapped_column(default=False, nullable=False)
    is_system_message: Mapped[bool] = mapped_column(default=False, nullable=False)

    # Relationships
    ticket: Mapped[Ticket] = relationship(
        back_populates="messages",
        foreign_keys=[ticket_id],
        lazy="noload",
        uselist=False,
    )
    author: Mapped[User] = relationship(
        foreign_keys=[author_id],
        lazy="joined",
        innerjoin=True,
        uselist=False,
    )
    attachments: Mapped[list[TicketAttachment]] = relationship(
        back_populates="ticket_message",
        cascade="all, delete",
        passive_deletes=True,
        lazy="selectin",
    )
