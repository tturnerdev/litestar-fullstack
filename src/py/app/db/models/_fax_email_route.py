from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.db.models._fax_number import FaxNumber


class FaxEmailRoute(UUIDv7AuditBase):
    """Maps a fax number to an email delivery address."""

    __tablename__ = "fax_email_route"
    __pii_columns__ = {"email_address"}
    fax_number_id: Mapped[UUID] = mapped_column(ForeignKey("fax_number.id", ondelete="cascade"), nullable=False)
    email_address: Mapped[str] = mapped_column(String(length=320), nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    notify_on_failure: Mapped[bool] = mapped_column(default=True, nullable=False)

    fax_number: Mapped[FaxNumber] = relationship(
        back_populates="email_routes",
        foreign_keys="FaxEmailRoute.fax_number_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
