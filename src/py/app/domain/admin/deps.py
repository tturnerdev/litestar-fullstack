"""Admin domain dependencies."""

from __future__ import annotations

from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.admin.services import AuditLogService, DefaultPermissionTemplateService
from app.lib.deps import create_service_provider

provide_audit_log_service = create_service_provider(
    AuditLogService,
    load=[selectinload(m.AuditLog.actor)],
    error_messages={
        "duplicate_key": "Audit log entry already exists.",
        "integrity": "Audit log operation failed.",
    },
)

provide_default_permission_template_service = create_service_provider(
    DefaultPermissionTemplateService,
    error_messages={
        "duplicate_key": "Default permission entry already exists.",
        "integrity": "Default permission template operation failed.",
    },
)

__all__ = ("provide_audit_log_service", "provide_default_permission_template_service")
