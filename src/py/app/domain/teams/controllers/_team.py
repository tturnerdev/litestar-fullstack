"""Team Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, Request, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.teams.guards import requires_team_admin, requires_team_membership, requires_team_ownership
from app.domain.teams.schemas import Team, TeamCreate, TeamUpdate
from app.domain.teams.services import TeamService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class TeamController(Controller):
    """Teams."""

    tags = ["Teams"]
    dependencies = create_service_dependencies(
        TeamService,
        key="teams_service",
        load=[selectinload(m.Team.tags), selectinload(m.Team.members)],
        filters={
            "id_filter": UUID,
            "search": "name",
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "name",
            "sort_order": "asc",
        },
    ) | {
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(component="team/list", operation_id="ListTeams", path="/api/teams")
    async def list_teams(
        self,
        teams_service: TeamService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[Team]:
        """List teams that your account can access.

        Args:
            teams_service: Team Service
            current_user: Current User
            filters: Filters

        Returns:
            OffsetPagination[Team]
        """
        if not teams_service.can_view_all(current_user):
            results, total = await teams_service.list_and_count(
                *filters,
                m.Team.id.in_(
                    select(m.TeamMember.team_id).where(m.TeamMember.user_id == current_user.id).scalar_subquery()
                ),
            )
        else:
            results, total = await teams_service.list_and_count(*filters)
        return teams_service.to_schema(results, total, filters, schema_type=Team)

    @post(operation_id="CreateTeam", path="/api/teams")
    async def create_team(
        self,
        request: Request[m.User, Token, Any],
        teams_service: TeamService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: TeamCreate,
    ) -> Team:
        """Create a new team.

        Args:
            request: The HTTP request.
            teams_service: Team Service
            audit_service: Audit log service
            current_user: Current User
            data: Team Create

        Returns:
            Team
        """
        obj = data.to_dict()
        obj.update({"owner_id": current_user.id, "owner": current_user})
        db_obj = await teams_service.create(obj)
        after = capture_snapshot(db_obj)

        await log_audit(
            audit_service,
            action="team.created",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="team",
            target_id=db_obj.id,
            target_label=db_obj.name,
            before=None,
            after=after,
            request=request,
        )

        return teams_service.to_schema(db_obj, schema_type=Team)

    @get(operation_id="GetTeam", path="/api/teams/{team_id:uuid}", guards=[requires_team_membership])
    async def get_team(
        self,
        teams_service: TeamService,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team to retrieve.")],
    ) -> Team:
        """Get details about a team.

        Args:
            teams_service: Team Service
            team_id: Team ID

        Returns:
            Team
        """
        db_obj = await teams_service.get(team_id)
        return teams_service.to_schema(db_obj, schema_type=Team)

    @patch(operation_id="UpdateTeam", path="/api/teams/{team_id:uuid}", guards=[requires_team_admin])
    async def update_team(
        self,
        request: Request[m.User, Token, Any],
        data: TeamUpdate,
        teams_service: TeamService,
        audit_service: AuditLogService,
        current_user: m.User,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team to update.")],
    ) -> Team:
        """Update a team.

        Args:
            request: The HTTP request.
            data: Team Update
            teams_service: Team Service
            audit_service: Audit log service
            current_user: Current User
            team_id: Team ID

        Returns:
            Team
        """
        before_obj = await teams_service.get(team_id)
        before = capture_snapshot(before_obj)

        await teams_service.update(
            item_id=team_id,
            data=data.to_dict(),
        )

        fresh_obj = await teams_service.get_one(id=team_id)
        after = capture_snapshot(fresh_obj)

        await log_audit(
            audit_service,
            action="team.updated",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="team",
            target_id=team_id,
            target_label=fresh_obj.name,
            before=before,
            after=after,
            request=request,
        )

        return teams_service.to_schema(fresh_obj, schema_type=Team)

    @delete(operation_id="DeleteTeam", path="/api/teams/{team_id:uuid}", guards=[requires_team_ownership])
    async def delete_team(
        self,
        request: Request[m.User, Token, Any],
        teams_service: TeamService,
        audit_service: AuditLogService,
        current_user: m.User,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team to delete.")],
    ) -> None:
        """Delete a team.

        Args:
            request: The HTTP request.
            teams_service: Team Service
            audit_service: Audit log service
            current_user: Current User
            team_id: Team ID
        """
        team = await teams_service.get(team_id)
        before = capture_snapshot(team)
        team_name = team.name
        _ = await teams_service.delete(team_id)

        await log_audit(
            audit_service,
            action="team.deleted",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="team",
            target_id=team_id,
            target_label=team_name,
            before=before,
            after=None,
            request=request,
        )
