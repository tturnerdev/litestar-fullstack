from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.db.models._fax_email_route import FaxEmailRoute
    from app.db.models._fax_message import FaxMessage
    from app.db.models._team import Team
    from app.db.models._user import User


class FaxNumber(UUIDv7AuditBase):
    """A fax DID assigned to a user."""

    __tablename__ = "fax_number"
    __pii_columns__ = {"number", "label"}
    user_id: Mapped[UUID] = mapped_column(ForeignKey("user_account.id", ondelete="cascade"), nullable=False)
    team_id: Mapped[UUID | None] = mapped_column(ForeignKey("team.id", ondelete="set null"), nullable=True, default=None)
    number: Mapped[str] = mapped_column(String(length=20), nullable=False, unique=True, index=True)
    label: Mapped[str | None] = mapped_column(String(length=100), nullable=True, default=None)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)

    user: Mapped[User] = relationship(
        foreign_keys="FaxNumber.user_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
        viewonly=True,
    )
    team: Mapped[Team | None] = relationship(
        foreign_keys="FaxNumber.team_id",
        uselist=False,
        lazy="joined",
        viewonly=True,
    )
    email_routes: Mapped[list[FaxEmailRoute]] = relationship(
        back_populates="fax_number",
        cascade="all, delete",
        passive_deletes=True,
        lazy="selectin",
    )
    messages: Mapped[list[FaxMessage]] = relationship(
        back_populates="fax_number",
        cascade="all, delete",
        passive_deletes=True,
        lazy="noload",
    )
