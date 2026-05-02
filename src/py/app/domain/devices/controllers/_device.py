"""Device Controllers."""

from __future__ import annotations

from datetime import date, datetime
from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import joinedload, selectinload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.devices.guards import requires_device_ownership
from app.domain.devices.schemas import Device, DeviceCreate, DeviceUpdate
from app.domain.devices.services import DeviceService
from app.domain.notifications.deps import provide_notifications_service
from app.domain.teams.guards import requires_feature_permission
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService
    from app.domain.notifications.services import NotificationService

_SNAPSHOT_EXCLUDE: frozenset[str] = frozenset(
    {"id", "sa_orm_sentinel", "created_at", "updated_at", "hashed_password", "totp_secret", "backup_codes"}
)


def _capture_snapshot(obj: Any) -> dict[str, Any]:
    """Serialize a SQLAlchemy model instance to a plain dict for audit details."""
    mapper = sa_inspect(type(obj))
    result: dict[str, Any] = {}
    for col in mapper.columns:
        key = col.key
        if key in _SNAPSHOT_EXCLUDE:
            continue
        try:
            value = getattr(obj, key)
        except Exception:  # noqa: BLE001, S112
            continue
        if isinstance(value, UUID):
            value = str(value)
        elif isinstance(value, (datetime, date)):
            value = value.isoformat()
        result[key] = value
    return result


async def _log_audit(
    audit_service: AuditLogService,
    *,
    action: str,
    actor: m.User,
    target_type: str,
    target_id: UUID,
    target_label: str,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    request: Request[Any, Any, Any] | None = None,
) -> None:
    """Write an audit log entry with optional before/after diff."""
    details: dict[str, Any] = {}
    if before is not None or after is not None:
        if before is None:
            details = {"before": None, "after": after}
        elif after is None:
            details = {"before": before, "after": None}
        else:
            changed_before: dict[str, Any] = {}
            changed_after: dict[str, Any] = {}
            for key in set(before) | set(after):
                if before.get(key) != after.get(key):
                    changed_before[key] = before.get(key)
                    changed_after[key] = after.get(key)
            if changed_before or changed_after:
                details = {"before": changed_before, "after": changed_after}

    await audit_service.log_action(
        action=action,
        actor_id=actor.id,
        actor_email=actor.email,
        actor_name=actor.name,
        target_type=target_type,
        target_id=str(target_id),
        target_label=target_label,
        details=details or None,
        request=request,
    )


class DeviceController(Controller):
    """Devices."""

    tags = ["Devices"]
    dependencies = create_service_dependencies(
        DeviceService,
        key="devices_service",
        load=[
            selectinload(m.Device.lines).joinedload(m.DeviceLineAssignment.extension),
            joinedload(m.Device.location),
            joinedload(m.Device.connection),
        ],
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

    @get(
        operation_id="ListDevices",
        path="/api/devices",
        guards=[requires_feature_permission("devices", "view")],
    )
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
        return devices_service.to_schema_enriched(results, total, filters)

    @post(
        operation_id="CreateDevice",
        path="/api/devices",
        guards=[requires_feature_permission("devices", "edit")],
    )
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
        after = _capture_snapshot(db_obj)
        await _log_audit(
            audit_service,
            action="device.created",
            actor=current_user,
            target_type="device",
            target_id=db_obj.id,
            target_label=db_obj.name,
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
        return devices_service.to_schema_enriched(db_obj)

    @get(
        operation_id="GetDevice",
        path="/api/devices/{device_id:uuid}",
        guards=[requires_feature_permission("devices", "view"), requires_device_ownership],
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
        return devices_service.to_schema_enriched(db_obj)

    @patch(
        operation_id="UpdateDevice",
        path="/api/devices/{device_id:uuid}",
        guards=[requires_feature_permission("devices", "edit"), requires_device_ownership],
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
        before = _capture_snapshot(await devices_service.get(device_id))
        await devices_service.update(
            item_id=device_id,
            data=data.to_dict(),
        )
        fresh_obj = await devices_service.get_one(id=device_id)
        after = _capture_snapshot(fresh_obj)
        await _log_audit(
            audit_service,
            action="device.updated",
            actor=current_user,
            target_type="device",
            target_id=device_id,
            target_label=fresh_obj.name,
            before=before,
            after=after,
            request=request,
        )
        return devices_service.to_schema_enriched(fresh_obj)

    @delete(
        operation_id="DeleteDevice",
        path="/api/devices/{device_id:uuid}",
        guards=[requires_feature_permission("devices", "edit"), requires_device_ownership],
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
        before = _capture_snapshot(db_obj)
        target_label = db_obj.name
        owner_id = db_obj.user_id
        await devices_service.delete(device_id)
        await _log_audit(
            audit_service,
            action="device.deleted",
            actor=current_user,
            target_type="device",
            target_id=device_id,
            target_label=target_label,
            before=before,
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
