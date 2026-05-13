"""Admin domain controllers."""

from app.domain.admin.controllers._attachments import AdminAttachmentsController
from app.domain.admin.controllers._audit import AuditController
from app.domain.admin.controllers._dashboard import DashboardController
from app.domain.admin.controllers._teams import AdminTeamsController
from app.domain.admin.controllers._users import AdminUsersController

__all__ = (
    "AdminAttachmentsController",
    "AdminTeamsController",
    "AdminUsersController",
    "AuditController",
    "DashboardController",
)
