"""Admin Device Templates Controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from advanced_alchemy.service.pagination import OffsetPagination
from litestar import Controller, delete, get, patch, post
from litestar.datastructures import CacheControlHeader
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT

from app.domain.accounts.guards import requires_superuser
from app.domain.admin.deps import provide_audit_log_service
from app.domain.admin.schemas import (
    DeviceTemplateCreate,
    DeviceTemplateDetail,
    DeviceTemplateList,
    DeviceTemplateUpdate,
)
from app.domain.admin.services import DeviceTemplateService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from litestar import Request
    from litestar.security.jwt import Token

    from app.db import models as m
    from app.domain.admin.services import AuditLogService


class AdminDeviceTemplatesController(Controller):
    """Admin device template management endpoints."""

    tags = ["Admin"]
    path = "/api/admin/device-templates"
    guards = [requires_superuser]
    dependencies = create_service_dependencies(
        DeviceTemplateService,
        key="template_service",
        filters={
            "id_filter": UUID,
            "search": "manufacturer,model,display_name",
            "pagination_type": "limit_offset",
            "pagination_size": 25,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    ) | {
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(
        operation_id="AdminListDeviceTemplates",
        summary="List device templates",
        description="Returns a paginated list of device templates with search across manufacturer, model, and display name. Results are cached for 5 minutes. Requires superuser access.",
        path="/",
        cache=300,
        cache_control=CacheControlHeader(private=True, max_age=300),
    )
    async def list_templates(
        self,
        template_service: DeviceTemplateService,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[DeviceTemplateList]:
        """List all device templates with search and pagination."""
        results, total = await template_service.list_and_count(*filters)
        return template_service.to_schema(results, total, filters, schema_type=DeviceTemplateList)

    @post(
        operation_id="AdminCreateDeviceTemplate",
        summary="Create a device template",
        description="Creates a new device template and records an audit log entry. Emits a device_template_created event. Requires superuser access.",
        path="/",
        status_code=HTTP_201_CREATED,
    )
    async def create_template(
        self,
        request: Request[m.User, Token, Any],
        template_service: DeviceTemplateService,
        audit_service: AuditLogService,
        data: DeviceTemplateCreate,
    ) -> DeviceTemplateDetail:
        """Create a new device template."""
        db_obj = await template_service.create(data.to_dict())
        after = capture_snapshot(db_obj)
        result = template_service.to_schema(db_obj, schema_type=DeviceTemplateDetail)
        await log_audit(
            audit_service,
            action="admin.device_template.created",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="device_template",
            target_id=db_obj.id,
            target_label=f"{db_obj.manufacturer} {db_obj.model}",
            before=None,
            after=after,
            request=request,
        )
        request.app.emit(event_id="device_template_created", template_id=db_obj.id)
        return result

    @get(
        operation_id="AdminGetDeviceTemplate",
        summary="Get device template details",
        description="Retrieves a single device template by its UUID, including all configuration fields. Requires superuser access.",
        path="/{template_id:uuid}",
    )
    async def get_template(
        self,
        template_service: DeviceTemplateService,
        template_id: Annotated[UUID, Parameter(title="Template ID", description="The device template to retrieve.")],
    ) -> DeviceTemplateDetail:
        """Get a device template by ID."""
        db_obj = await template_service.get(template_id)
        return template_service.to_schema(db_obj, schema_type=DeviceTemplateDetail)

    @patch(
        operation_id="AdminUpdateDeviceTemplate",
        summary="Update a device template",
        description="Partially updates a device template. Captures before/after snapshots for the audit log and emits a device_template_updated event. Requires superuser access.",
        path="/{template_id:uuid}",
    )
    async def update_template(
        self,
        request: Request[m.User, Token, Any],
        template_service: DeviceTemplateService,
        audit_service: AuditLogService,
        data: DeviceTemplateUpdate,
        template_id: Annotated[UUID, Parameter(title="Template ID", description="The device template to update.")],
    ) -> DeviceTemplateDetail:
        """Update a device template."""
        db_obj = await template_service.get(template_id)
        before = capture_snapshot(db_obj)
        db_obj = await template_service.update(
            item_id=template_id,
            data=data.to_dict(),
        )
        after = capture_snapshot(db_obj)
        result = template_service.to_schema(db_obj, schema_type=DeviceTemplateDetail)
        await log_audit(
            audit_service,
            action="admin.device_template.updated",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="device_template",
            target_id=db_obj.id,
            target_label=f"{db_obj.manufacturer} {db_obj.model}",
            before=before,
            after=after,
            request=request,
        )
        request.app.emit(event_id="device_template_updated", template_id=db_obj.id)
        return result

    @delete(
        operation_id="AdminDeleteDeviceTemplate",
        summary="Delete a device template",
        description="Permanently deletes a device template. Records the deletion in the audit log with a before snapshot. Requires superuser access.",
        path="/{template_id:uuid}",
        status_code=HTTP_204_NO_CONTENT,
        return_dto=None,
    )
    async def delete_template(
        self,
        request: Request[m.User, Token, Any],
        template_service: DeviceTemplateService,
        audit_service: AuditLogService,
        template_id: Annotated[UUID, Parameter(title="Template ID", description="The device template to delete.")],
    ) -> None:
        """Delete a device template."""
        db_obj = await template_service.get(template_id)
        before = capture_snapshot(db_obj)
        target_label = f"{db_obj.manufacturer} {db_obj.model}"
        request.app.emit(event_id="device_template_deleted", template_id=template_id)
        await template_service.delete(template_id)
        await log_audit(
            audit_service,
            action="admin.device_template.deleted",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="device_template",
            target_id=template_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )
