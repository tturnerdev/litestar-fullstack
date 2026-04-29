"""Admin Devices Controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from advanced_alchemy.service.pagination import OffsetPagination
from litestar import Controller, get
from litestar.params import Dependency

from app.db import models as m
from app.domain.accounts.guards import requires_superuser
from app.domain.admin.schemas import AdminDeviceStats, AdminDeviceSummary
from app.domain.devices.services import DeviceService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes, LimitOffset


class AdminDevicesController(Controller):
    tags = ["Admin"]
    path = "/api/admin/devices"
    guards = [requires_superuser]
    dependencies = create_service_dependencies(
        DeviceService,
        key="device_service",
        filters={
            "id_filter": UUID,
            "search": "name,sip_username,mac_address",
            "pagination_type": "limit_offset",
            "pagination_size": 25,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    )

    @get(operation_id="AdminListDevices", path="/")
    async def list_devices(
        self,
        device_service: DeviceService,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[AdminDeviceSummary]:
        results, total = await device_service.list_and_count(*filters)
        limit_offset = next((f for f in filters if hasattr(f, "limit")), None)
        items = [
            AdminDeviceSummary(
                id=d.id,
                name=d.name,
                device_type=d.device_type,
                status=d.status,
                is_active=d.is_active,
                mac_address=d.mac_address,
                model=d.model,
                ip_address=d.ip_address,
                sip_username=d.sip_username,
                owner_email=d.user.email if d.user else None,
                team_name=d.team.name if d.team else None,
                last_seen_at=d.last_seen_at,
                created_at=d.created_at,
            )
            for d in results
        ]
        return OffsetPagination(
            items=items,
            total=total,
            limit=limit_offset.limit if limit_offset else 25,
            offset=limit_offset.offset if limit_offset else 0,
        )

    @get(operation_id="AdminGetDeviceStats", path="/stats")
    async def get_stats(
        self,
        device_service: DeviceService,
    ) -> AdminDeviceStats:
        total = await device_service.count()
        active = await device_service.count(m.Device.is_active.is_(True))
        online = await device_service.count(m.Device.status == "online")
        offline = await device_service.count(m.Device.status == "offline")
        error = await device_service.count(m.Device.status == "error")

        all_devices = await device_service.list()
        type_counts: dict[str, int] = {}
        for d in all_devices:
            type_counts[d.device_type] = type_counts.get(d.device_type, 0) + 1

        return AdminDeviceStats(
            total=total,
            active=active,
            online=online,
            offline=offline,
            error=error,
            by_type=type_counts,
        )
