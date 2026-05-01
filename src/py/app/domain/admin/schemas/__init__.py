"""Admin domain schemas."""

from app.domain.admin.schemas._admin_bulk_import import (
    BulkImportPreview,
    BulkImportPreviewRow,
    BulkImportResult,
)
from app.domain.admin.schemas._admin_device_templates import (
    DeviceTemplateCreate,
    DeviceTemplateDetail,
    DeviceTemplateList,
    DeviceTemplateLookup,
    DeviceTemplateUpdate,
)
from app.domain.admin.schemas._admin_devices import AdminDeviceStats, AdminDeviceSummary
from app.domain.admin.schemas._admin_fax import AdminFaxMessageSummary, AdminFaxNumberSummary, AdminFaxStats
from app.domain.admin.schemas._admin_gateway import AdminGatewaySettings, AdminGatewaySettingsUpdate
from app.domain.admin.schemas._admin_music_on_hold import (
    MusicOnHoldCreate,
    MusicOnHoldDetail,
    MusicOnHoldList,
    MusicOnHoldUpdate,
)
from app.domain.admin.schemas._admin_support import AdminSupportStats, AdminTicketSummary
from app.domain.admin.schemas._admin_system import AdminSystemStatus, WorkerQueueInfo
from app.domain.admin.schemas._admin_voice import AdminExtensionSummary, AdminPhoneNumberSummary, AdminVoiceStats
from app.domain.admin.schemas._audit import AuditLogEntry
from app.domain.admin.schemas._dashboard import ActivityLogEntry, AdminTrends, DashboardStats, RecentActivity, TrendPoint
from app.domain.admin.schemas._teams import AdminTeamDetail, AdminTeamSummary, AdminTeamUpdate
from app.domain.admin.schemas._users import AdminUserDetail, AdminUserSummary, AdminUserUpdate

__all__ = (
    "ActivityLogEntry",
    "AdminDeviceStats",
    "BulkImportPreview",
    "BulkImportPreviewRow",
    "BulkImportResult",
    "AdminDeviceSummary",
    "AdminExtensionSummary",
    "AdminFaxMessageSummary",
    "AdminFaxNumberSummary",
    "AdminFaxStats",
    "AdminGatewaySettings",
    "AdminGatewaySettingsUpdate",
    "AdminPhoneNumberSummary",
    "AdminSupportStats",
    "AdminTeamDetail",
    "AdminTeamSummary",
    "AdminTeamUpdate",
    "AdminTicketSummary",
    "AdminSystemStatus",
    "AdminTrends",
    "AdminUserDetail",
    "AdminUserSummary",
    "AdminUserUpdate",
    "AdminVoiceStats",
    "AuditLogEntry",
    "DashboardStats",
    "DeviceTemplateCreate",
    "DeviceTemplateDetail",
    "DeviceTemplateList",
    "DeviceTemplateLookup",
    "DeviceTemplateUpdate",
    "MusicOnHoldCreate",
    "MusicOnHoldDetail",
    "MusicOnHoldList",
    "MusicOnHoldUpdate",
    "RecentActivity",
    "TrendPoint",
    "WorkerQueueInfo",
)
