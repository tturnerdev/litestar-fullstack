from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._voice_enums import PhoneNumberType

if TYPE_CHECKING:
    from app.db.models._extension import Extension
    from app.db.models._team import Team
    from app.db.models._user import User


class PhoneNumber(UUIDv7AuditBase):
    """A DID (Direct Inward Dial) number assigned to a user."""

    __tablename__ = "phone_number"
    __table_args__ = {"comment": "Phone numbers assigned to users"}

    user_id: Mapped[UUID] = mapped_column(ForeignKey("user_account.id", ondelete="cascade"), nullable=False)
    number: Mapped[str] = mapped_column(String(length=20), nullable=False, unique=True, index=True)
    label: Mapped[str | None] = mapped_column(String(length=100), nullable=True, default=None)
    number_type: Mapped[PhoneNumberType] = mapped_column(
        String(length=20),
        default=PhoneNumberType.LOCAL,
        nullable=False,
    )
    caller_id_name: Mapped[str | None] = mapped_column(String(length=50), nullable=True, default=None)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    team_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("team.id", ondelete="set null"), nullable=True, default=None
    )

    user: Mapped[User] = relationship(
        foreign_keys="PhoneNumber.user_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
    team: Mapped[Team | None] = relationship(
        foreign_keys="PhoneNumber.team_id",
        uselist=False,
        lazy="joined",
    )
    extensions: Mapped[list[Extension]] = relationship(
        back_populates="phone_number",
        lazy="noload",
        uselist=True,
    )
