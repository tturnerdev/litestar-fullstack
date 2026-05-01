"""Admin domain controllers."""

from app.domain.admin.controllers._admin_device_templates import AdminDeviceTemplatesController
from app.domain.admin.controllers._admin_devices import AdminDevicesController
from app.domain.admin.controllers._admin_fax import AdminFaxController
from app.domain.admin.controllers._admin_gateway import AdminGatewayController
from app.domain.admin.controllers._admin_music_on_hold import AdminMusicOnHoldController
from app.domain.admin.controllers._admin_support import AdminSupportController
from app.domain.admin.controllers._admin_system import AdminSystemController
from app.domain.admin.controllers._admin_voice import AdminVoiceController
from app.domain.admin.controllers._audit import AuditController
from app.domain.admin.controllers._dashboard import DashboardController
from app.domain.admin.controllers._teams import AdminTeamsController
from app.domain.admin.controllers._users import AdminUsersController

__all__ = (
    "AdminDeviceTemplatesController",
    "AdminDevicesController",
    "AdminFaxController",
    "AdminGatewayController",
    "AdminMusicOnHoldController",
    "AdminSupportController",
    "AdminSystemController",
    "AdminTeamsController",
    "AdminUsersController",
    "AdminVoiceController",
    "AuditController",
    "DashboardController",
)
