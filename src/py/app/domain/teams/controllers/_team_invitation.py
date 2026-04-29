"""Team Invitation Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any

from litestar import Controller, Request, delete, get, post
from litestar.di import Provide
from litestar.exceptions import HTTPException
from litestar.params import Dependency
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.accounts.deps import provide_users_service
from app.domain.admin.deps import provide_audit_log_service
from app.domain.notifications.deps import provide_notifications_service
from app.domain.teams.deps import provide_team_members_service, provide_teams_service
from app.domain.teams.schemas import TeamInvitation, TeamInvitationCreate
from app.domain.teams.services import TeamInvitationService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies
from app.lib.schema import Message

if TYPE_CHECKING:
    from uuid import UUID

    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service import OffsetPagination
    from litestar.security.jwt import Token

    from app.domain.accounts.services import UserService
    from app.domain.admin.services import AuditLogService
    from app.domain.notifications.services import NotificationService
    from app.domain.teams.services import TeamMemberService, TeamService
    from app.lib.email import AppEmailService


class TeamInvitationController(Controller):
    """Team Invitations."""

    path = "/api/teams/{team_id:uuid}/invitations"
    tags = ["Teams"]
    dependencies = create_service_dependencies(
        TeamInvitationService,
        key="team_invitations_service",
        load=[selectinload(m.TeamInvitation.team)],
        error_messages={
            "duplicate_key": "Invitation already exists.",
            "integrity": "Team invitation operation failed.",
        },
        filters={
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    ) | {
        "teams_service": Provide(provide_teams_service),
        "team_members_service": Provide(provide_team_members_service),
        "audit_service": Provide(provide_audit_log_service),
        "notifications_service": Provide(provide_notifications_service),
        "users_service": Provide(provide_users_service),
    }

    @post(operation_id="CreateTeamInvitation", path="")
    async def create_team_invitation(
        self,
        current_user: m.User,
        team_invitations_service: TeamInvitationService,
        teams_service: TeamService,
        audit_service: AuditLogService,
        notifications_service: NotificationService,
        users_service: UserService,
        app_mailer: AppEmailService,
        request: Request[m.User, Token, Any],
        team_id: UUID,
        data: TeamInvitationCreate,
    ) -> TeamInvitation:
        """Create a new team invitation.

        Args:
            current_user: The current user sending the invitation.
            team_invitations_service: The team invitation service.
            teams_service: The teams service.
            audit_service: Audit log service.
            app_mailer: Email service for sending notifications.
            request: The request object.
            team_id: The team id.
            data: The data to create the team invitation with.

        Raises:
            HTTPException: If the invitee is already a team member

        Returns:
            The created team invitation.
        """
        team = await teams_service.get(team_id)
        if any(member.email == data.email for member in team.members):
            raise HTTPException(status_code=400, detail="User is already a member of this team")
        payload = data.to_dict()
        payload["team_id"] = team_id
        payload["invited_by"] = current_user
        db_obj = await team_invitations_service.create(payload)
        after = capture_snapshot(db_obj)
        request.app.emit(event_id="team_invitation_created", invitation_id=db_obj.id, mailer=app_mailer)

        await log_audit(
            audit_service,
            action="team.invitation_create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="team_invitation",
            target_id=db_obj.id,
            target_label=f"{data.email} -> {team.name}",
            before=None,
            after=after,
            request=request,
        )

        try:
            invited_user = await users_service.get_one_or_none(email=data.email)
            if invited_user is not None:
                await notifications_service.notify(
                    user_id=invited_user.id,
                    title="Team Invitation",
                    message=f"You've been invited to join team '{team.name}'.",
                    category="team",
                    action_url=f"/teams/{team_id}",
                )
        except Exception:
            pass

        return team_invitations_service.to_schema(db_obj, schema_type=TeamInvitation)

    @get(operation_id="ListTeamInvitations", path="")
    async def list_team_invitations(
        self,
        team_invitations_service: TeamInvitationService,
        team_id: UUID,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[TeamInvitation]:
        """List team invitations.

        Args:
            team_id: The ID of the team to list the invitations for.
            team_invitations_service: The team invitation service.
            filters: Filter and pagination parameters

        Returns:
            The list of team invitations.
        """
        db_objs, total = await team_invitations_service.list_and_count(*filters, m.TeamInvitation.team_id == team_id)
        return team_invitations_service.to_schema(db_objs, total, filters, schema_type=TeamInvitation)

    @delete(operation_id="DeleteTeamInvitation", path="/{invitation_id:uuid}")
    async def delete_team_invitation(
        self,
        request: Request[m.User, Token, Any],
        current_user: m.User,
        team_invitations_service: TeamInvitationService,
        audit_service: AuditLogService,
        team_id: UUID,
        invitation_id: UUID,
    ) -> None:
        """Delete an invitation.

        Args:
            request: The HTTP request.
            current_user: The current user.
            team_invitations_service: The team invitation service.
            audit_service: Audit log service.
            team_id: The ID of the team to delete the invitation for.
            invitation_id: The ID of the invitation to delete.

        Raises:
            HTTPException: If the invitation does not belong to the team
        """
        invitation = await team_invitations_service.get(invitation_id)
        if invitation.team_id != team_id:
            raise HTTPException(status_code=400, detail="Invitation does not belong to this team")
        before = capture_snapshot(invitation)
        await team_invitations_service.delete(item_id=invitation_id)

        await log_audit(
            audit_service,
            action="team.invitation_delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="team_invitation",
            target_id=invitation_id,
            target_label=invitation.email,
            before=before,
            after=None,
            request=request,
        )

    @post(operation_id="AcceptTeamInvitation", path="/{invitation_id:uuid}/accept")
    async def accept_team_invitation(
        self,
        request: Request[m.User, Token, Any],
        current_user: m.User,
        team_invitations_service: TeamInvitationService,
        team_members_service: TeamMemberService,
        audit_service: AuditLogService,
        notifications_service: NotificationService,
        teams_service: TeamService,
        team_id: UUID,
        invitation_id: UUID,
    ) -> Message:
        """Accept an invitation.

        Args:
            request: The HTTP request.
            team_id: The ID of the team to accept the invitation for.
            invitation_id: The ID of the invitation to accept.
            team_invitations_service: The team invitation service.
            team_members_service: The team member service.
            audit_service: Audit log service.
            current_user: The current user.

        Raises:
            HTTPException: If the invitation is invalid or the user cannot accept it

        Returns:
            A message indicating that the team invitation has been accepted.
        """
        db_obj = await team_invitations_service.get(item_id=invitation_id)
        if db_obj.team_id != team_id:
            raise HTTPException(status_code=400, detail="Invitation does not belong to this team")
        if db_obj.is_accepted:
            raise HTTPException(status_code=400, detail="Invitation has already been accepted")
        if db_obj.email != current_user.email:
            raise HTTPException(status_code=400, detail="You are not authorized to accept this invitation")
        existing_membership = await team_members_service.get_one_or_none(
            team_id=team_id,
            user_id=current_user.id,
        )
        if existing_membership is not None:
            raise HTTPException(status_code=400, detail="User is already a member of this team")
        _ = await team_members_service.create(
            {
                "team_id": team_id,
                "user_id": current_user.id,
                "role": db_obj.role,
                "is_owner": False,
            }
        )
        await team_invitations_service.update(item_id=invitation_id, data={"is_accepted": True})

        await log_audit(
            audit_service,
            action="team.invitation_accept",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="team_invitation",
            target_id=invitation_id,
            target_label=db_obj.email,
            request=request,
            metadata={"team_id": str(team_id), "role": db_obj.role},
        )

        try:
            team = await teams_service.get(team_id)
            owner = next((member for member in team.members if member.is_owner), None)
            if owner is not None:
                await notifications_service.notify(
                    user_id=owner.user_id,
                    title="Invitation Accepted",
                    message=f"{current_user.email} has joined team '{team.name}'.",
                    category="team",
                    action_url=f"/teams/{team_id}",
                )
        except Exception:
            pass

        return Message(message="Team invitation accepted")

    @post(operation_id="RejectTeamInvitation", path="/{invitation_id:uuid}/reject")
    async def reject_team_invitation(
        self,
        request: Request[m.User, Token, Any],
        current_user: m.User,
        team_invitations_service: TeamInvitationService,
        audit_service: AuditLogService,
        team_id: UUID,
        invitation_id: UUID,
    ) -> Message:
        """Reject an invitation.

        Raises:
            HTTPException: If the invitation is invalid or the user cannot reject it

        Returns:
            A message indicating that the team invitation has been rejected.
        """
        db_obj = await team_invitations_service.get(item_id=invitation_id)
        if db_obj.team_id != team_id:
            raise HTTPException(status_code=400, detail="Invitation does not belong to this team")
        if db_obj.email != current_user.email:
            raise HTTPException(status_code=400, detail="You are not authorized to reject this invitation")
        await team_invitations_service.delete(item_id=invitation_id)

        await log_audit(
            audit_service,
            action="team.invitation_reject",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="team_invitation",
            target_id=invitation_id,
            target_label=db_obj.email,
            request=request,
            metadata={"team_id": str(team_id)},
        )

        return Message(message="Team invitation rejected")
