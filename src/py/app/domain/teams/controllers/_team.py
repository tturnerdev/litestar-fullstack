"""Team Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from litestar import Controller, delete, get, patch, post, put
from litestar.datastructures import (
    UploadFile,  # noqa: TC002  (resolved at runtime by Litestar for the request signature)
)
from litestar.enums import RequestEncodingType
from litestar.params import Body, Dependency, Parameter
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.attachments.services import AttachmentService
from app.domain.teams.guards import requires_team_admin, requires_team_membership, requires_team_ownership
from app.domain.teams.schemas import Team, TeamCreate, TeamUpdate
from app.domain.teams.services import TeamService
from app.lib.deps import create_service_dependencies, create_service_provider

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination

    from app.domain.admin.services import AuditLogService


class TeamController(Controller):
    """Teams."""

    tags = ["Teams"]
    dependencies = {
        **create_service_dependencies(
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
        ),
        "attachments_service": create_service_provider(AttachmentService),
        "audit_service": provide_audit_log_service,
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
    async def create_team(self, teams_service: TeamService, current_user: m.User, data: TeamCreate) -> Team:
        """Create a new team.

        Args:
            teams_service: Team Service
            current_user: Current User
            data: Team Create

        Returns:
            Team
        """
        obj = data.to_dict()
        obj.update({"owner_id": current_user.id, "owner": current_user})
        db_obj = await teams_service.create(obj)
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
        data: TeamUpdate,
        teams_service: TeamService,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team to update.")],
    ) -> Team:
        """Update a team.

        Args:
            data: Team Update
            teams_service: Team Service
            team_id: Team ID

        Returns:
            Team
        """
        await teams_service.update(
            item_id=team_id,
            data=data.to_dict(),
        )

        fresh_obj = await teams_service.get_one(id=team_id)
        return teams_service.to_schema(fresh_obj, schema_type=Team)

    @delete(operation_id="DeleteTeam", path="/api/teams/{team_id:uuid}", guards=[requires_team_ownership])
    async def delete_team(
        self,
        teams_service: TeamService,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team to delete.")],
    ) -> None:
        """Delete a team.

        Args:
            teams_service: Team Service
            team_id: Team ID
        """
        _ = await teams_service.delete(team_id)

    @put(operation_id="SetTeamLogo", path="/api/teams/{team_id:uuid}/logo", guards=[requires_team_admin])
    async def set_team_logo(
        self,
        teams_service: TeamService,
        attachments_service: AttachmentService,
        audit_service: AuditLogService,
        current_user: m.User,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team to set the logo for.")],
        data: Annotated[UploadFile, Body(media_type=RequestEncodingType.MULTI_PART)],
    ) -> Team:
        """Upload and set a team's logo.

        Args:
            teams_service: Team Service
            attachments_service: The attachments service.
            audit_service: The audit log service.
            current_user: Current User
            team_id: Team ID
            data: The uploaded image.

        Returns:
            Team
        """
        team = await teams_service.get(team_id)
        previous_logo_id = team.logo_id
        # excluding the previous logo from the team's used-bytes calculation so
        # a same-size replacement at the quota does not spuriously 413.
        attachment = await attachments_service.create_from_upload(
            data,
            uploaded_by_id=current_user.id,
            team_id=team_id,
            purpose=m.AttachmentPurpose.TEAM_LOGO,
            excluding_attachment_id=previous_logo_id,
        )
        await teams_service.update(
            item_id=team_id,
            data={"logo_id": attachment.id, "logo_url": f"/api/uploads/{attachment.id}/content"},
        )
        if previous_logo_id and previous_logo_id != attachment.id:
            previous = await attachments_service.get_one_or_none(id=previous_logo_id)
            if previous is not None:
                await attachments_service.delete_with_object(previous)
        await audit_service.log_action(
            "team.logo.set",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="team",
            target_id=str(team_id),
            target_label=team.name,
            details={"attachment_id": str(attachment.id), "size_bytes": attachment.size_bytes},
        )
        fresh_obj = await teams_service.get_one(id=team_id)
        return teams_service.to_schema(fresh_obj, schema_type=Team)
