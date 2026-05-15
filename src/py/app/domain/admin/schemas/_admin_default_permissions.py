"""Admin default permission template schemas."""

from uuid import UUID

from app.db.models._feature_area import FeatureArea
from app.db.models._team_roles import TeamRoles
from app.lib.schema import CamelizedBaseStruct


class DefaultPermissionEntry(CamelizedBaseStruct):
    """A single permission entry in the default template."""

    role: TeamRoles
    feature_area: FeatureArea
    can_view: bool = False
    can_edit: bool = False


class DefaultPermissionTemplate(CamelizedBaseStruct):
    """A persisted default permission template entry."""

    id: UUID
    role: TeamRoles
    feature_area: FeatureArea
    can_view: bool
    can_edit: bool


class DefaultPermissionTemplateUpdate(CamelizedBaseStruct):
    """Bulk update payload for the default permission template."""

    permissions: list[DefaultPermissionEntry]
