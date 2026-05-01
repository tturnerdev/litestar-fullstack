from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._call_routing_enums import IvrGreetingType

if TYPE_CHECKING:
    from app.db.models._ivr_menu_option import IvrMenuOption
    from app.db.models._team import Team


class IvrMenu(UUIDv7AuditBase):
    """An interactive voice response menu for caller self-service routing."""

    __tablename__ = "ivr_menu"
    __table_args__ = {"comment": "IVR auto-attendant menus"}

    team_id: Mapped[UUID] = mapped_column(
        ForeignKey("team.id", ondelete="cascade"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(length=255), nullable=False, index=True)
    greeting_type: Mapped[IvrGreetingType] = mapped_column(
        String(length=50),
        default=IvrGreetingType.NONE,
        nullable=False,
    )
    greeting_text: Mapped[str | None] = mapped_column(String(length=2000), nullable=True, default=None)
    greeting_file_url: Mapped[str | None] = mapped_column(String(length=500), nullable=True, default=None)
    timeout_seconds: Mapped[int] = mapped_column(default=5, nullable=False)
    max_retries: Mapped[int] = mapped_column(default=3, nullable=False)
    timeout_destination: Mapped[str | None] = mapped_column(String(length=255), nullable=True, default=None)
    invalid_destination: Mapped[str | None] = mapped_column(String(length=255), nullable=True, default=None)

    # Relationships
    team: Mapped[Team] = relationship(
        foreign_keys="IvrMenu.team_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
    options: Mapped[list[IvrMenuOption]] = relationship(
        back_populates="ivr_menu",
        cascade="all, delete",
        passive_deletes=True,
        lazy="selectin",
        order_by="IvrMenuOption.sort_order",
    )
