"""Device Actions Controller — reboot, reprovision, and line management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from litestar import Controller, get, post, put
from litestar.di import Provide
from litestar.params import Parameter

from app.domain.devices.deps import provide_devices_service
from app.domain.devices.schemas import (
    Device,
    DeviceActionResponse,
    DeviceLineAssignment,
    SetDeviceLinesRequest,
)

if TYPE_CHECKING:
    from app.domain.devices.services import DeviceService


class DeviceActionsController(Controller):
    """Device action and line assignment endpoints."""

    tags = ["Devices"]
    dependencies = {
        "devices_service": Provide(provide_devices_service),
    }

    @post(operation_id="RebootDevice", path="/api/devices/{device_id:uuid}/reboot")
    async def reboot_device(
        self,
        devices_service: DeviceService,
        device_id: Annotated[UUID, Parameter(title="Device ID", description="The device to reboot.")],
    ) -> DeviceActionResponse:
        device = await devices_service.reboot_device(device_id)
        return DeviceActionResponse(
            device_id=device.id,
            action="reboot",
            status="initiated",
            message="Reboot command has been sent to the device.",
        )

    @post(operation_id="ReprovisionDevice", path="/api/devices/{device_id:uuid}/reprovision")
    async def reprovision_device(
        self,
        devices_service: DeviceService,
        device_id: Annotated[UUID, Parameter(title="Device ID", description="The device to reprovision.")],
    ) -> DeviceActionResponse:
        device = await devices_service.reprovision_device(device_id)
        return DeviceActionResponse(
            device_id=device.id,
            action="reprovision",
            status="initiated",
            message="Reprovisioning has been initiated for the device.",
        )

    @get(operation_id="ListDeviceLines", path="/api/devices/{device_id:uuid}/lines")
    async def list_device_lines(
        self,
        devices_service: DeviceService,
        device_id: Annotated[UUID, Parameter(title="Device ID", description="The device to list lines for.")],
    ) -> list[DeviceLineAssignment]:
        device = await devices_service.get(device_id)
        return [
            devices_service.to_schema(line, schema_type=DeviceLineAssignment)
            for line in device.lines
        ]

    @put(operation_id="SetDeviceLines", path="/api/devices/{device_id:uuid}/lines")
    async def set_device_lines(
        self,
        devices_service: DeviceService,
        device_id: Annotated[UUID, Parameter(title="Device ID", description="The device to set lines for.")],
        data: SetDeviceLinesRequest,
    ) -> Device:
        lines_data = [line.to_dict() for line in data.lines]
        device = await devices_service.set_device_lines(device_id, lines_data)
        return devices_service.to_schema(device, schema_type=Device)
