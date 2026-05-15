"""Admin domain services."""

from app.domain.admin.services._audit import AuditLogService
from app.domain.admin.services._default_permission_template import DefaultPermissionTemplateService
from app.domain.admin.services._device_template import DeviceTemplateService
from app.domain.admin.services._music_on_hold import MusicOnHoldService

__all__ = ("AuditLogService", "DefaultPermissionTemplateService", "DeviceTemplateService", "MusicOnHoldService")
