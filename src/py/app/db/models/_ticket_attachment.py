from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import BigInteger, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.db.models._ticket import Ticket
    from app.db.models._ticket_message import TicketMessage
    from app.db.models._user import User


class TicketAttachment(UUIDv7AuditBase):
    """File attachments on ticket messages."""

    __tablename__ = "ticket_attachment"
    __table_args__ = {"comment": "File attachments for support ticket messages"}

    ticket_message_id: Mapped[UUID] = mapped_column(
        ForeignKey("ticket_message.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ticket_id: Mapped[UUID] = mapped_column(
        ForeignKey("ticket.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    uploaded_by_id: Mapped[UUID] = mapped_column(
        ForeignKey("user_account.id", ondelete="CASCADE"),
        nullable=False,
    )
    file_name: Mapped[str] = mapped_column(String(length=255), nullable=False)
    file_path: Mapped[str] = mapped_column(String(length=500), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    content_type: Mapped[str] = mapped_column(String(length=100), nullable=False)
    is_inline: Mapped[bool] = mapped_column(default=False, nullable=False)

    # Relationships
    ticket_message: Mapped[TicketMessage] = relationship(
        back_populates="attachments",
        foreign_keys=[ticket_message_id],
        lazy="noload",
        uselist=False,
    )
    ticket: Mapped[Ticket] = relationship(
        back_populates="attachments",
        foreign_keys=[ticket_id],
        lazy="noload",
        uselist=False,
    )
    uploaded_by: Mapped[User] = relationship(
        foreign_keys=[uploaded_by_id],
        lazy="joined",
        uselist=False,
    )
