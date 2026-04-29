"""Device Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.devices.guards import requires_device_ownership
from app.domain.devices.schemas import Device, DeviceCreate, DeviceUpdate
from app.domain.devices.services import DeviceService
from app.domain.notifications.deps import provide_notifications_service
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService
    from app.domain.notifications.services import NotificationService


class DeviceController(Controller):
    """Devices."""

    tags = ["Devices"]
    dependencies = create_service_dependencies(
        DeviceService,
        key="devices_service",
        load=[selectinload(m.Device.lines)],
        filters={
            "id_filter": UUID,
            "search": "name",
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "name",
            "sort_order": "asc",
        },
    ) | {
        "audit_service": Provide(provide_audit_log_service),
        "notifications_service": Provide(provide_notifications_service),
    }

    @get(operation_id="ListDevices", path="/api/devices")
    async def list_devices(
        self,
        devices_service: DeviceService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[Device]:
        """List devices for the current user.

        Args:
            devices_service: Device Service
            current_user: Current User
            filters: Filters

        Returns:
            OffsetPagination[Device]
        """
        if current_user.is_superuser:
            results, total = await devices_service.list_and_count(*filters)
        else:
            results, total = await devices_service.list_and_count(
                *filters,
                m.Device.user_id == current_user.id,
            )
        return devices_service.to_schema(results, total, filters, schema_type=Device)

    @post(operation_id="CreateDevice", path="/api/devices")
    async def create_device(
        self,
        request: Request[m.User, Token, Any],
        devices_service: DeviceService,
        audit_service: AuditLogService,
        notifications_service: NotificationService,
        current_user: m.User,
        data: DeviceCreate,
    ) -> Device:
        """Register a new device.

        Args:
            request: The current request
            devices_service: Device Service
            audit_service: Audit Log Service
            current_user: Current User
            data: Device Create

        Returns:
            Device
        """
        obj = data.to_dict()
        obj["user_id"] = current_user.id
        db_obj = await devices_service.create(obj)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="device.create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="device",
            target_id=db_obj.id,
            target_label=db_obj.name,
            before=None,
            after=after,
            request=request,
        )
        try:
            await notifications_service.notify(
                user_id=current_user.id,
                title="Device Registered",
                message=f"Your device '{db_obj.name}' has been registered.",
                category="device",
                action_url=f"/devices/{db_obj.id}",
            )
        except Exception:
            pass
        return devices_service.to_schema(db_obj, schema_type=Device)

    @get(
        operation_id="GetDevice",
        path="/api/devices/{device_id:uuid}",
        guards=[requires_device_ownership],
    )
    async def get_device(
        self,
        devices_service: DeviceService,
        device_id: Annotated[UUID, Parameter(title="Device ID", description="The device to retrieve.")],
    ) -> Device:
        """Get details about a device.

        Args:
            devices_service: Device Service
            device_id: Device ID

        Returns:
            Device
        """
        db_obj = await devices_service.get(device_id)
        return devices_service.to_schema(db_obj, schema_type=Device)

    @patch(
        operation_id="UpdateDevice",
        path="/api/devices/{device_id:uuid}",
        guards=[requires_device_ownership],
    )
    async def update_device(
        self,
        request: Request[m.User, Token, Any],
        data: DeviceUpdate,
        devices_service: DeviceService,
        audit_service: AuditLogService,
        current_user: m.User,
        device_id: Annotated[UUID, Parameter(title="Device ID", description="The device to update.")],
    ) -> Device:
        """Update a device.

        Args:
            request: The current request
            data: Device Update
            devices_service: Device Service
            audit_service: Audit Log Service
            current_user: Current User
            device_id: Device ID

        Returns:
            Device
        """
        before = capture_snapshot(await devices_service.get(device_id))
        await devices_service.update(
            item_id=device_id,
            data=data.to_dict(),
        )
        fresh_obj = await devices_service.get_one(id=device_id)
        after = capture_snapshot(fresh_obj)
        await log_audit(
            audit_service,
            action="device.update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="device",
            target_id=device_id,
            target_label=fresh_obj.name,
            before=before,
            after=after,
            request=request,
        )
        return devices_service.to_schema(fresh_obj, schema_type=Device)

    @delete(
        operation_id="DeleteDevice",
        path="/api/devices/{device_id:uuid}",
        guards=[requires_device_ownership],
    )
    async def delete_device(
        self,
        request: Request[m.User, Token, Any],
        devices_service: DeviceService,
        audit_service: AuditLogService,
        notifications_service: NotificationService,
        current_user: m.User,
        device_id: Annotated[UUID, Parameter(title="Device ID", description="The device to delete.")],
    ) -> None:
        """Delete a device.

        Args:
            request: The current request
            devices_service: Device Service
            audit_service: Audit Log Service
            current_user: Current User
            device_id: Device ID
        """
        db_obj = await devices_service.get(device_id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.name
        owner_id = db_obj.user_id
        await devices_service.delete(device_id)
        await log_audit(
            audit_service,
            action="device.delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="device",
            target_id=device_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )
        try:
            await notifications_service.notify(
                user_id=owner_id,
                title="Device Removed",
                message=f"Your device '{target_label}' has been removed.",
                category="device",
                action_url="/devices",
            )
        except Exception:
            pass
