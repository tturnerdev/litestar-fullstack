"""Admin domain schemas."""

from app.domain.admin.schemas._admin_devices import AdminDeviceStats, AdminDeviceSummary
from app.domain.admin.schemas._admin_fax import AdminFaxMessageSummary, AdminFaxNumberSummary, AdminFaxStats
from app.domain.admin.schemas._admin_support import AdminSupportStats, AdminTicketSummary
from app.domain.admin.schemas._admin_voice import AdminExtensionSummary, AdminPhoneNumberSummary, AdminVoiceStats
from app.domain.admin.schemas._audit import AuditLogEntry
from app.domain.admin.schemas._dashboard import ActivityLogEntry, DashboardStats, RecentActivity
from app.domain.admin.schemas._teams import AdminTeamDetail, AdminTeamSummary, AdminTeamUpdate
from app.domain.admin.schemas._users import AdminUserDetail, AdminUserSummary, AdminUserUpdate

__all__ = (
    "ActivityLogEntry",
    "AdminDeviceStats",
    "AdminDeviceSummary",
    "AdminExtensionSummary",
    "AdminFaxMessageSummary",
    "AdminFaxNumberSummary",
    "AdminFaxStats",
    "AdminPhoneNumberSummary",
    "AdminSupportStats",
    "AdminTeamDetail",
    "AdminTeamSummary",
    "AdminTeamUpdate",
    "AdminTicketSummary",
    "AdminUserDetail",
    "AdminUserSummary",
    "AdminUserUpdate",
    "AdminVoiceStats",
    "AuditLogEntry",
    "DashboardStats",
    "RecentActivity",
)
