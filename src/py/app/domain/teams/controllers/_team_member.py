"""Team Member Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any

from advanced_alchemy.exceptions import IntegrityError
from litestar import Controller, Request, delete, patch, post
from litestar.di import Provide
from litestar.params import Parameter
from litestar.status_codes import HTTP_202_ACCEPTED

from app.db import models as m
from app.domain.accounts.deps import provide_users_service
from app.domain.admin.deps import provide_audit_log_service
from app.domain.notifications.deps import provide_notifications_service
from app.domain.teams.deps import provide_team_members_service, provide_teams_service
from app.domain.teams.schemas import Team, TeamMember, TeamMemberModify, TeamMemberUpdate
from app.lib.audit import capture_snapshot, log_audit

if TYPE_CHECKING:
    from uuid import UUID

    from litestar.security.jwt import Token

    from app.domain.accounts.services import UserService
    from app.domain.admin.services import AuditLogService
    from app.domain.notifications.services import NotificationService
    from app.domain.teams.services import TeamMemberService, TeamService


class TeamMemberController(Controller):
    """Team Members."""

    tags = ["Team Members"]
    dependencies = {
        "teams_service": Provide(provide_teams_service),
        "team_members_service": Provide(provide_team_members_service),
        "users_service": Provide(provide_users_service),
        "audit_service": Provide(provide_audit_log_service),
        "notifications_service": Provide(provide_notifications_service),
    }

    @post(operation_id="AddMemberToTeam", path="/api/teams/{team_id:uuid}/members")
    async def add_member_to_team(
        self,
        request: Request[m.User, Token, Any],
        teams_service: TeamService,
        team_members_service: TeamMemberService,
        users_service: UserService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: TeamMemberModify,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team to update.")],
    ) -> Team:
        """Add a member to a team.

        Args:
            request: The HTTP request.
            teams_service: Team Service
            team_members_service: Team Member Service
            users_service: User Service
            audit_service: Audit log service
            current_user: Current User
            data: Team Member Modify
            team_id: Team ID

        Raises:
            IntegrityError: If the user is already a member of the team.

        Returns:
            Team
        """
        user_obj = await users_service.get_one(email=data.user_name)
        existing_membership = await team_members_service.get_one_or_none(team_id=team_id, user_id=user_obj.id)
        if existing_membership is not None:
            msg = "User is already a member of the team."
            raise IntegrityError(msg)
        member = await team_members_service.create(
            {
                "team_id": team_id,
                "user_id": user_obj.id,
                "role": m.TeamRoles.MEMBER,
                "is_owner": False,
            }
        )
        after = capture_snapshot(member)
        team_obj = await teams_service.get(team_id)

        await log_audit(
            audit_service,
            action="team.member_add",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="team_member",
            target_id=member.id,
            target_label=f"{user_obj.email} -> {team_obj.name}",
            before=None,
            after=after,
            request=request,
        )

        return teams_service.to_schema(team_obj, schema_type=Team)

    @delete(
        operation_id="RemoveMemberFromTeam", path="/api/teams/{team_id:uuid}/members", status_code=HTTP_202_ACCEPTED
    )
    async def remove_member_from_team(
        self,
        request: Request[m.User, Token, Any],
        teams_service: TeamService,
        team_members_service: TeamMemberService,
        users_service: UserService,
        audit_service: AuditLogService,
        notifications_service: NotificationService,
        current_user: m.User,
        data: TeamMemberModify,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team to delete.")],
    ) -> Team:
        """Revoke a member's access to a team.

        Args:
            request: The HTTP request.
            teams_service: Team Service
            team_members_service: Team Member Service
            users_service: User Service
            audit_service: Audit log service
            current_user: Current User
            data: Team Member Modify
            team_id: Team ID

        Raises:
            IntegrityError: If the user is not a member of the team.

        Returns:
            Team
        """
        user_obj = await users_service.get_one(email=data.user_name)
        membership = await team_members_service.get_one_or_none(team_id=team_id, user_id=user_obj.id)
        if membership is None:
            msg = "User is not a member of this team."
            raise IntegrityError(msg)
        before = capture_snapshot(membership)
        await team_members_service.delete(membership.id)
        team_obj = await teams_service.get(team_id)

        await log_audit(
            audit_service,
            action="team.member_remove",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="team_member",
            target_id=membership.id,
            target_label=f"{user_obj.email} -> {team_obj.name}",
            before=before,
            after=None,
            request=request,
        )

        try:
            await notifications_service.notify(
                user_id=user_obj.id,
                title="Removed from Team",
                message=f"You have been removed from team '{team_obj.name}'.",
                category="team",
                action_url=f"/teams/{team_id}",
            )
        except Exception:
            pass

        return teams_service.to_schema(team_obj, schema_type=Team)

    @patch(operation_id="UpdateTeamMember", path="/api/teams/{team_id:uuid}/members/{user_id:uuid}")
    async def update_team_member(
        self,
        request: Request[m.User, Token, Any],
        team_members_service: TeamMemberService,
        audit_service: AuditLogService,
        current_user: m.User,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team to update.")],
        user_id: Annotated[UUID, Parameter(title="User ID", description="The user to update.")],
        data: TeamMemberUpdate,
    ) -> TeamMember:
        """Update a team member's role.

        Raises:
            IntegrityError: If the user is not a member of the team.

        Returns:
            The updated team member.
        """
        membership = await team_members_service.get_one_or_none(team_id=team_id, user_id=user_id)
        if membership is None:
            msg = "User is not a member of this team."
            raise IntegrityError(msg)
        before = capture_snapshot(membership)
        updated = await team_members_service.update(item_id=membership.id, data={"role": data.role})
        after = capture_snapshot(updated)

        await log_audit(
            audit_service,
            action="team.member_update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="team_member",
            target_id=membership.id,
            before=before,
            after=after,
            request=request,
        )

        return team_members_service.to_schema(updated, schema_type=TeamMember)
