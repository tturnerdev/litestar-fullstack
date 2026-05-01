"""Team Role Permission Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any

from litestar import Controller, get, put
from litestar.di import Provide
from litestar.params import Parameter

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.teams.deps import provide_team_role_permissions_service
from app.domain.teams.guards import requires_team_admin, requires_team_membership
from app.domain.teams.schemas import TeamRolePermission, TeamRolePermissionUpdate
from app.lib.audit import capture_snapshot, log_audit

if TYPE_CHECKING:
    from uuid import UUID

    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService
    from app.domain.teams.services import TeamRolePermissionService


class TeamRolePermissionController(Controller):
    """Team Role Permissions."""

    tags = ["Team Permissions"]
    dependencies = {
        "permissions_service": Provide(provide_team_role_permissions_service),
        "audit_service": Provide(provide_audit_log_service),
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
        request: Request[m.User, Token, Any],
        permissions_service: TeamRolePermissionService,
        audit_service: AuditLogService,
        current_user: m.User,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team to update permissions for.")],
        data: TeamRolePermissionUpdate,
    ) -> list[TeamRolePermission]:
        existing = await permissions_service.list(m.TeamRolePermission.team_id == team_id)
        before_permissions = [capture_snapshot(item) for item in existing]
        for item in existing:
            await permissions_service.delete(item.id)

        created = []
        after_permissions = []
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
            after_permissions.append(capture_snapshot(obj))
        await log_audit(
            audit_service,
            action="team.permissions.updated",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="team_role_permission",
            target_id=team_id,
            target_label=f"team:{team_id}",
            before={"permissions": before_permissions},
            after={"permissions": after_permissions},
            request=request,
        )
        return [permissions_service.to_schema(r, schema_type=TeamRolePermission) for r in created]
