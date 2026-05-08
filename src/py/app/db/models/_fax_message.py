from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import BigInteger, ForeignKey, String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._fax_enums import FaxDirection, FaxStatus

if TYPE_CHECKING:
    from app.db.models._fax_number import FaxNumber


class FaxMessage(UUIDv7AuditBase):
    """Record of a sent or received fax."""

    __tablename__ = "fax_message"
    __pii_columns__ = {"remote_number", "remote_name", "delivered_to_emails"}
    fax_number_id: Mapped[UUID] = mapped_column(ForeignKey("fax_number.id", ondelete="cascade"), nullable=False)
    direction: Mapped[FaxDirection] = mapped_column(String(length=20), nullable=False)
    remote_number: Mapped[str] = mapped_column(String(length=20), nullable=False)
    remote_name: Mapped[str | None] = mapped_column(String(length=100), nullable=True, default=None)
    page_count: Mapped[int] = mapped_column(default=0, nullable=False)
    status: Mapped[FaxStatus] = mapped_column(String(length=20), nullable=False)
    file_path: Mapped[str] = mapped_column(String(length=500), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    error_message: Mapped[str | None] = mapped_column(String(length=500), nullable=True, default=None)
    delivered_to_emails: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True, default=None)
    received_at: Mapped[datetime] = mapped_column(nullable=False)

    fax_number: Mapped[FaxNumber] = relationship(
        back_populates="messages",
        foreign_keys="FaxMessage.fax_number_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
