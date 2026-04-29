"""Teams domain schemas."""

from app.domain.teams.schemas._invitation import TeamInvitation, TeamInvitationCreate
from app.domain.teams.schemas._member import TeamMember, TeamMemberModify, TeamMemberUpdate
from app.domain.teams.schemas._permission import TeamRolePermission, TeamRolePermissionEntry, TeamRolePermissionUpdate
from app.domain.teams.schemas._team import Team, TeamCreate, TeamTag, TeamUpdate
from app.lib.schema import Message

__all__ = (
    "Message",
    "Team",
    "TeamCreate",
    "TeamInvitation",
    "TeamInvitationCreate",
    "TeamMember",
    "TeamMemberModify",
    "TeamMemberUpdate",
    "TeamRolePermission",
    "TeamRolePermissionEntry",
    "TeamRolePermissionUpdate",
    "TeamTag",
    "TeamUpdate",
)
