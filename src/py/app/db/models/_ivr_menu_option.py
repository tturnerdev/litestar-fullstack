from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.db.models._ivr_menu import IvrMenu


class IvrMenuOption(UUIDv7AuditBase):
    """A single key-press option within an IVR menu."""

    __tablename__ = "ivr_menu_option"
    __table_args__ = (
        UniqueConstraint("ivr_menu_id", "digit"),
        {"comment": "Key-press options for IVR menus"},
    )

    ivr_menu_id: Mapped[UUID] = mapped_column(
        ForeignKey("ivr_menu.id", ondelete="cascade"),
        nullable=False,
        index=True,
    )
    digit: Mapped[str] = mapped_column(String(length=2), nullable=False)
    label: Mapped[str] = mapped_column(String(length=255), nullable=False)
    destination: Mapped[str] = mapped_column(String(length=255), nullable=False)
    sort_order: Mapped[int] = mapped_column(default=0, nullable=False)

    # Relationships
    ivr_menu: Mapped[IvrMenu] = relationship(
        back_populates="options",
        foreign_keys="IvrMenuOption.ivr_menu_id",
        innerjoin=True,
        uselist=False,
    )
