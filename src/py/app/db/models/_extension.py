from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.db.models._do_not_disturb import DoNotDisturb
    from app.db.models._forwarding_rule import ForwardingRule
    from app.db.models._phone_number import PhoneNumber
    from app.db.models._user import User
    from app.db.models._voicemail_box import VoicemailBox


class Extension(UUIDv7AuditBase):
    """Internal extension for routing calls within the system."""

    __tablename__ = "extension"
    __table_args__ = {"comment": "Internal phone extensions"}

    user_id: Mapped[UUID] = mapped_column(ForeignKey("user_account.id", ondelete="cascade"), nullable=False)
    extension_number: Mapped[str] = mapped_column(String(length=10), nullable=False, unique=True, index=True)
    phone_number_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("phone_number.id", ondelete="set null"), nullable=True, default=None
    )
    display_name: Mapped[str] = mapped_column(String(length=100), nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)

    user: Mapped[User] = relationship(
        foreign_keys="Extension.user_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
    phone_number: Mapped[PhoneNumber | None] = relationship(
        back_populates="extensions",
        foreign_keys="Extension.phone_number_id",
        uselist=False,
        lazy="joined",
    )
    voicemail_box: Mapped[VoicemailBox | None] = relationship(
        back_populates="extension",
        uselist=False,
        lazy="noload",
        cascade="all, delete",
    )
    forwarding_rules: Mapped[list[ForwardingRule]] = relationship(
        back_populates="extension",
        lazy="noload",
        uselist=True,
        cascade="all, delete",
    )
    do_not_disturb: Mapped[DoNotDisturb | None] = relationship(
        back_populates="extension",
        uselist=False,
        lazy="noload",
        cascade="all, delete",
    )
