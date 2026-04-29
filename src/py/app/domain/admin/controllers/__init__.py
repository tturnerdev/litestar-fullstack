"""Admin domain controllers."""

from app.domain.admin.controllers._admin_devices import AdminDevicesController
from app.domain.admin.controllers._admin_fax import AdminFaxController
from app.domain.admin.controllers._admin_support import AdminSupportController
from app.domain.admin.controllers._admin_system import AdminSystemController
from app.domain.admin.controllers._admin_voice import AdminVoiceController
from app.domain.admin.controllers._audit import AuditController
from app.domain.admin.controllers._dashboard import DashboardController
from app.domain.admin.controllers._teams import AdminTeamsController
from app.domain.admin.controllers._users import AdminUsersController

__all__ = (
    "AdminDevicesController",
    "AdminFaxController",
    "AdminSupportController",
    "AdminSystemController",
    "AdminTeamsController",
    "AdminUsersController",
    "AdminVoiceController",
    "AuditController",
    "DashboardController",
)
