"""Admin Device Templates Controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from advanced_alchemy.service.pagination import OffsetPagination
from litestar import Controller, delete, get, patch, post
from litestar.params import Dependency, Parameter

from app.domain.accounts.guards import requires_superuser
from app.domain.admin.schemas import (
    DeviceTemplateCreate,
    DeviceTemplateDetail,
    DeviceTemplateList,
    DeviceTemplateUpdate,
)
from app.domain.admin.services import DeviceTemplateService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes, LimitOffset


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
    )

    @get(operation_id="AdminListDeviceTemplates", path="/")
    async def list_templates(
        self,
        template_service: DeviceTemplateService,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[DeviceTemplateList]:
        """List all device templates with search and pagination."""
        results, total = await template_service.list_and_count(*filters)
        limit_offset = next((f for f in filters if hasattr(f, "limit")), None)
        items = [
            DeviceTemplateList(
                id=t.id,
                manufacturer=t.manufacturer,
                model=t.model,
                display_name=t.display_name,
                device_type=t.device_type,
                is_active=t.is_active,
                image_url=t.image_url,
                created_at=t.created_at,
                updated_at=t.updated_at,
            )
            for t in results
        ]
        return OffsetPagination(
            items=items,
            total=total,
            limit=limit_offset.limit if limit_offset else 25,
            offset=limit_offset.offset if limit_offset else 0,
        )

    @post(operation_id="AdminCreateDeviceTemplate", path="/")
    async def create_template(
        self,
        template_service: DeviceTemplateService,
        data: DeviceTemplateCreate,
    ) -> DeviceTemplateDetail:
        """Create a new device template."""
        db_obj = await template_service.create(data.to_dict())
        return DeviceTemplateDetail(
            id=db_obj.id,
            manufacturer=db_obj.manufacturer,
            model=db_obj.model,
            display_name=db_obj.display_name,
            device_type=db_obj.device_type,
            wireframe_data=db_obj.wireframe_data,
            provisioning_template=db_obj.provisioning_template,
            template_variables=db_obj.template_variables,
            image_url=db_obj.image_url,
            is_active=db_obj.is_active,
            created_at=db_obj.created_at,
            updated_at=db_obj.updated_at,
        )

    @get(operation_id="AdminGetDeviceTemplate", path="/{template_id:uuid}")
    async def get_template(
        self,
        template_service: DeviceTemplateService,
        template_id: Annotated[UUID, Parameter(title="Template ID", description="The device template to retrieve.")],
    ) -> DeviceTemplateDetail:
        """Get a device template by ID."""
        db_obj = await template_service.get(template_id)
        return DeviceTemplateDetail(
            id=db_obj.id,
            manufacturer=db_obj.manufacturer,
            model=db_obj.model,
            display_name=db_obj.display_name,
            device_type=db_obj.device_type,
            wireframe_data=db_obj.wireframe_data,
            provisioning_template=db_obj.provisioning_template,
            template_variables=db_obj.template_variables,
            image_url=db_obj.image_url,
            is_active=db_obj.is_active,
            created_at=db_obj.created_at,
            updated_at=db_obj.updated_at,
        )

    @patch(operation_id="AdminUpdateDeviceTemplate", path="/{template_id:uuid}")
    async def update_template(
        self,
        template_service: DeviceTemplateService,
        data: DeviceTemplateUpdate,
        template_id: Annotated[UUID, Parameter(title="Template ID", description="The device template to update.")],
    ) -> DeviceTemplateDetail:
        """Update a device template."""
        db_obj = await template_service.update(
            item_id=template_id,
            data=data.to_dict(),
        )
        return DeviceTemplateDetail(
            id=db_obj.id,
            manufacturer=db_obj.manufacturer,
            model=db_obj.model,
            display_name=db_obj.display_name,
            device_type=db_obj.device_type,
            wireframe_data=db_obj.wireframe_data,
            provisioning_template=db_obj.provisioning_template,
            template_variables=db_obj.template_variables,
            image_url=db_obj.image_url,
            is_active=db_obj.is_active,
            created_at=db_obj.created_at,
            updated_at=db_obj.updated_at,
        )

    @delete(operation_id="AdminDeleteDeviceTemplate", path="/{template_id:uuid}")
    async def delete_template(
        self,
        template_service: DeviceTemplateService,
        template_id: Annotated[UUID, Parameter(title="Template ID", description="The device template to delete.")],
    ) -> None:
        """Delete a device template."""
        await template_service.delete(template_id)
