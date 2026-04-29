from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._feature_area import FeatureArea
from app.db.models._team_roles import TeamRoles

if TYPE_CHECKING:
    from app.db.models._team import Team


class TeamRolePermission(UUIDv7AuditBase):
    """Per-role permission grants scoped to a team and feature area."""

    __tablename__ = "team_role_permission"
    __table_args__ = (UniqueConstraint("team_id", "role", "feature_area"),)

    team_id: Mapped[UUID] = mapped_column(ForeignKey("team.id", ondelete="cascade"), nullable=False, index=True)
    role: Mapped[TeamRoles] = mapped_column(String(length=50), nullable=False, index=True)
    feature_area: Mapped[FeatureArea] = mapped_column(String(length=50), nullable=False, index=True)
    can_view: Mapped[bool] = mapped_column(default=False, nullable=False)
    can_edit: Mapped[bool] = mapped_column(default=False, nullable=False)

    team: Mapped[Team] = relationship(
        back_populates="permissions",
        foreign_keys="TeamRolePermission.team_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
