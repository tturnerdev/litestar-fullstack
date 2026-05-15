"""Team domain signals/events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from litestar.events import listener

from app.domain.accounts.deps import provide_users_service
from app.domain.admin.deps import provide_default_permission_template_service
from app.domain.teams import deps
from app.lib.deps import provide_services

if TYPE_CHECKING:
    from uuid import UUID

    from app.lib.email import AppEmailService


logger = structlog.get_logger()


@listener("team_created")
async def team_created_event_handler(team_id: UUID) -> None:
    """Executes when a new team is created.

    Applies the default permission template to the new team.  If no
    custom defaults exist, the system falls back to the hardcoded
    defaults (ADMIN=full, MEMBER=view-only) via the guard logic.

    Args:
        team_id: The primary key of the team that was created.
    """
    await logger.ainfo("Running post team creation flow.")
    async with provide_services(
        deps.provide_teams_service,
        deps.provide_team_role_permissions_service,
        provide_default_permission_template_service,
    ) as (
        teams_service,
        permissions_service,
        template_service,
    ):
        obj = await teams_service.get_one_or_none(id=team_id)
        if obj is None:
            await logger.aerror("Could not locate the specified team", id=team_id)
            return

        await logger.ainfo("Found team", **obj.to_dict())

        # Load default permission template entries
        template_entries = await template_service.list()
        if not template_entries:
            await logger.ainfo(
                "No default permission template configured, using hardcoded defaults",
                team_id=team_id,
            )
            return

        try:
            await permissions_service.create_many(
                [
                    {
                        "team_id": team_id,
                        "role": entry.role,
                        "feature_area": entry.feature_area,
                        "can_view": entry.can_view,
                        "can_edit": entry.can_edit,
                    }
                    for entry in template_entries
                ]
            )
        except Exception:
            await logger.aerror(
                "Failed to apply default permission template to team",
                team_id=team_id,
                exc_info=True,
            )
            return

        await logger.ainfo(
            "Applied default permission template to new team",
            team_id=team_id,
            permissions_created=len(template_entries),
        )


@listener("team_invitation_created")
async def team_invitation_created_event_handler(invitation_id: UUID, mailer: AppEmailService) -> None:
    """Executes when a new team invitation is created.

    Args:
        invitation_id: The team invitation ID.
        mailer: The application email service.
    """
    await logger.ainfo("Running post team invitation creation flow.")
    async with provide_services(
        deps.provide_team_invitations_service, deps.provide_teams_service, provide_users_service
    ) as (
        team_invitations_service,
        teams_service,
        users_service,
    ):
        invitation = await team_invitations_service.get_one_or_none(id=invitation_id)
        if invitation is None:
            await logger.aerror("Could not locate the specified team invitation", id=invitation_id)
            return

        inviter = await users_service.get_one_or_none(id=invitation.invited_by_id)
        if inviter is None:
            await logger.aerror("Could not locate the inviter", id=invitation.invited_by_id)
            return

        team = await teams_service.get_one_or_none(id=invitation.team_id)
        if team is None:
            await logger.aerror("Could not locate the team", id=invitation.team_id)
            return

        try:
            await mailer.send_team_invitation_email(
                invitee_email=invitation.email,
                inviter_name=inviter.name or inviter.email,
                team_name=team.name,
                invitation_url=f"{mailer.base_url}/teams/{team.id}/invitations/{invitation.id}/accept",
            )
        except Exception:
            await logger.aerror("Failed to send team invitation email", invitation_id=invitation.id, exc_info=True)
            return

        await logger.ainfo("Sent team invitation email", invitation_id=invitation.id)


__all__ = (
    "team_created_event_handler",
    "team_invitation_created_event_handler",
)
