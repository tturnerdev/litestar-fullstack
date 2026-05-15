"""Admin Default Permission Template Controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar import Controller, get, put
from litestar.di import Provide

from app.domain.accounts.guards import requires_superuser
from app.domain.admin.deps import provide_audit_log_service, provide_default_permission_template_service
from app.domain.admin.schemas import (
    DefaultPermissionTemplate,
    DefaultPermissionTemplateUpdate,
)
from app.lib.audit import log_audit

if TYPE_CHECKING:
    from litestar import Request
    from litestar.security.jwt import Token

    from app.db import models as m
    from app.domain.admin.services import AuditLogService, DefaultPermissionTemplateService


class AdminDefaultPermissionsController(Controller):
    """Manage the default permission template applied to new teams."""

    tags = ["Admin"]
    path = "/api/admin/default-permissions"
    guards = [requires_superuser]
    dependencies = {
        "template_service": Provide(provide_default_permission_template_service),
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(
        operation_id="GetDefaultPermissions",
        summary="Get default permission template",
        description="Returns the default permission template that is applied when new teams are created. If no custom defaults have been saved, returns an empty list (the system falls back to ADMIN=full, MEMBER=view-only).",
    )
    async def get_default_permissions(
        self,
        template_service: DefaultPermissionTemplateService,
    ) -> list[DefaultPermissionTemplate]:
        results = await template_service.list()
        return [template_service.to_schema(item, schema_type=DefaultPermissionTemplate) for item in results]

    @put(
        operation_id="UpdateDefaultPermissions",
        summary="Update default permission template",
        description="Replaces the entire default permission template. Deletes all existing entries and creates the new set atomically. This template is applied when new teams are created. Records an audit log entry.",
    )
    async def update_default_permissions(
        self,
        request: Request[m.User, Token, Any],
        template_service: DefaultPermissionTemplateService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: DefaultPermissionTemplateUpdate,
    ) -> list[DefaultPermissionTemplate]:
        existing = await template_service.list()
        before_permissions = [
            {
                "role": item.role,
                "feature_area": item.feature_area,
                "can_view": item.can_view,
                "can_edit": item.can_edit,
            }
            for item in existing
        ]

        if existing:
            await template_service.delete_many([item.id for item in existing])

        created = await template_service.create_many(
            [
                {
                    "role": entry.role,
                    "feature_area": entry.feature_area,
                    "can_view": entry.can_view,
                    "can_edit": entry.can_edit,
                }
                for entry in data.permissions
            ]
        )

        after_permissions = [
            {
                "role": obj.role,
                "feature_area": obj.feature_area,
                "can_view": obj.can_view,
                "can_edit": obj.can_edit,
            }
            for obj in created
        ]

        result = [template_service.to_schema(item, schema_type=DefaultPermissionTemplate) for item in created]

        await log_audit(
            audit_service,
            action="admin.default_permissions.updated",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="default_permission_template",
            target_id=None,
            target_label="default_permission_template",
            request=request,
            before={"permissions": before_permissions},
            after={"permissions": after_permissions},
        )

        return result
