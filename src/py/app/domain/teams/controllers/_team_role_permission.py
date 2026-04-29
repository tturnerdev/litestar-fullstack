"""Team Role Permission Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from litestar import Controller, get, put
from litestar.di import Provide
from litestar.params import Parameter

from app.db import models as m
from app.domain.teams.deps import provide_team_role_permissions_service
from app.domain.teams.guards import requires_team_admin, requires_team_membership
from app.domain.teams.schemas import TeamRolePermission, TeamRolePermissionUpdate

if TYPE_CHECKING:
    from uuid import UUID

    from app.domain.teams.services import TeamRolePermissionService


class TeamRolePermissionController(Controller):
    """Team Role Permissions."""

    tags = ["Team Permissions"]
    dependencies = {
        "permissions_service": Provide(provide_team_role_permissions_service),
    }

    @get(
        operation_id="ListTeamPermissions",
        path="/api/teams/{team_id:uuid}/permissions",
        guards=[requires_team_membership],
    )
    async def list_team_permissions(
        self,
        permissions_service: TeamRolePermissionService,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team to retrieve permissions for.")],
    ) -> list[TeamRolePermission]:
        results = await permissions_service.list(m.TeamRolePermission.team_id == team_id)
        return [permissions_service.to_schema(r, schema_type=TeamRolePermission) for r in results]

    @put(
        operation_id="UpdateTeamPermissions",
        path="/api/teams/{team_id:uuid}/permissions",
        guards=[requires_team_admin],
    )
    async def update_team_permissions(
        self,
        permissions_service: TeamRolePermissionService,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team to update permissions for.")],
        data: TeamRolePermissionUpdate,
    ) -> list[TeamRolePermission]:
        existing = await permissions_service.list(m.TeamRolePermission.team_id == team_id)
        for item in existing:
            await permissions_service.delete(item.id)

        created = []
        for entry in data.permissions:
            obj = await permissions_service.create(
                {
                    "team_id": team_id,
                    "role": entry.role,
                    "feature_area": entry.feature_area,
                    "can_view": entry.can_view,
                    "can_edit": entry.can_edit,
                }
            )
            created.append(obj)
        return [permissions_service.to_schema(r, schema_type=TeamRolePermission) for r in created]
