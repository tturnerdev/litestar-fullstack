"""Team role permission schemas."""

from uuid import UUID

from app.db.models._feature_area import FeatureArea
from app.db.models._team_roles import TeamRoles
from app.lib.schema import CamelizedBaseStruct


class TeamRolePermission(CamelizedBaseStruct):
    id: UUID
    team_id: UUID
    role: TeamRoles
    feature_area: FeatureArea
    can_view: bool
    can_edit: bool


class TeamRolePermissionEntry(CamelizedBaseStruct):
    """A single permission entry for bulk upsert."""

    role: TeamRoles
    feature_area: FeatureArea
    can_view: bool = False
    can_edit: bool = False


class TeamRolePermissionUpdate(CamelizedBaseStruct):
    """Bulk update payload for team permissions."""

    permissions: list[TeamRolePermissionEntry]
