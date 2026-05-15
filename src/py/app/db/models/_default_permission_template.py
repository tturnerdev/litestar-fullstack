"""Default permission template model."""

from __future__ import annotations

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models._feature_area import FeatureArea
from app.db.models._team_roles import TeamRoles


class DefaultPermissionTemplate(UUIDv7AuditBase):
    """Stores the default permission template applied to new teams.

    Each row defines the default can_view / can_edit grant for a given
    role + feature_area combination.  When a new team is created, these
    rows are copied as ``TeamRolePermission`` entries.
    """

    __tablename__ = "default_permission_template"
    __table_args__ = (
        UniqueConstraint("role", "feature_area", name="uq_default_permission_template_role_feature_area"),
        {"comment": "Default permission template applied when creating new teams"},
    )

    role: Mapped[TeamRoles] = mapped_column(String(length=50), nullable=False, index=True)
    feature_area: Mapped[FeatureArea] = mapped_column(String(length=50), nullable=False, index=True)
    can_view: Mapped[bool] = mapped_column(default=False, nullable=False)
    can_edit: Mapped[bool] = mapped_column(default=False, nullable=False)

    def __repr__(self) -> str:
        return f"<DefaultPermissionTemplate id={self.id} role={self.role} feature_area={self.feature_area}>"
