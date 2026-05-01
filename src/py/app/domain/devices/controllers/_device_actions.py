"""Device Actions Controller — reboot, reprovision, line management, and screenshot proxy."""

from __future__ import annotations

import ipaddress
import logging
from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

import httpx
from litestar import Controller, Response, get, post, put
from litestar.di import Provide
from litestar.exceptions import NotFoundException, ValidationException
from litestar.params import Parameter

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.devices.deps import provide_devices_service
from app.domain.devices.schemas import (
    Device,
    DeviceActionResponse,
    DeviceLineAssignment,
    SetDeviceLinesRequest,
)
from app.lib.audit import capture_snapshot, log_audit

if TYPE_CHECKING:
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService
    from app.domain.devices.services import DeviceService

logger = logging.getLogger(__name__)


class DeviceActionsController(Controller):
    """Device action and line assignment endpoints."""

    tags = ["Devices"]
    dependencies = {
        "devices_service": Provide(provide_devices_service),
        "audit_service": Provide(provide_audit_log_service),
    }

    @post(operation_id="RebootDevice", path="/api/devices/{device_id:uuid}/reboot")
    async def reboot_device(
        self,
        request: Request[m.User, Token, Any],
        devices_service: DeviceService,
        audit_service: AuditLogService,
        current_user: m.User,
        device_id: Annotated[UUID, Parameter(title="Device ID", description="The device to reboot.")],
    ) -> DeviceActionResponse:
        device = await devices_service.reboot_device(device_id)
        await log_audit(
            audit_service,
            action="device.reboot",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="device",
            target_id=device.id,
            target_label=device.name,
            request=request,
        )
        return DeviceActionResponse(
            device_id=device.id,
            action="reboot",
            status="initiated",
            message="Reboot command has been sent to the device.",
        )

    @post(operation_id="ReprovisionDevice", path="/api/devices/{device_id:uuid}/reprovision")
    async def reprovision_device(
        self,
        request: Request[m.User, Token, Any],
        devices_service: DeviceService,
        audit_service: AuditLogService,
        current_user: m.User,
        device_id: Annotated[UUID, Parameter(title="Device ID", description="The device to reprovision.")],
    ) -> DeviceActionResponse:
        device = await devices_service.reprovision_device(device_id)
        await log_audit(
            audit_service,
            action="device.reprovision",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="device",
            target_id=device.id,
            target_label=device.name,
            request=request,
        )
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
        request: Request[m.User, Token, Any],
        devices_service: DeviceService,
        audit_service: AuditLogService,
        current_user: m.User,
        device_id: Annotated[UUID, Parameter(title="Device ID", description="The device to set lines for.")],
        data: SetDeviceLinesRequest,
    ) -> Device:
        before_device = await devices_service.get(device_id)
        before = capture_snapshot(before_device)
        lines_data = [line.to_dict() for line in data.lines]
        device = await devices_service.set_device_lines(device_id, lines_data)
        after = capture_snapshot(device)
        await log_audit(
            audit_service,
            action="device.set_lines",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="device",
            target_id=device.id,
            target_label=device.name,
            before=before,
            after=after,
            request=request,
        )
        return devices_service.to_schema(device, schema_type=Device)

    @get(
        operation_id="GetDeviceScreenshot",
        path="/api/devices/{device_id:uuid}/screenshot",
        media_type="image/bmp",
        include_in_schema=False,
    )
    async def get_device_screenshot(
        self,
        devices_service: DeviceService,
        device_id: Annotated[UUID, Parameter(title="Device ID", description="The device to capture.")],
        username: str = "admin",
        password: str = "admin",
    ) -> Response[bytes]:
        device = await devices_service.get(device_id)
        if not device.ip_address:
            raise NotFoundException(detail="Device has no IP address configured.")
        try:
            addr = ipaddress.ip_address(device.ip_address)
            if not addr.is_private:
                raise ValidationException(detail="Only private/LAN IP addresses are allowed.")
        except ValueError as exc:
            raise ValidationException(detail="Invalid device IP address.") from exc

        url = f"https://{device.ip_address}/servlet?m=mod_action&command=screenshot"
        try:
            async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(10.0)) as http:
                resp = await http.get(url, auth=(username, password))
                resp.raise_for_status()
        except httpx.TimeoutException:
            return Response(content=b"", status_code=504, media_type="text/plain")
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            return Response(content=b"", status_code=status if status in (401, 403) else 502, media_type="text/plain")
        except httpx.HTTPError:
            return Response(content=b"", status_code=502, media_type="text/plain")

        content_type = resp.headers.get("content-type", "image/bmp")
        return Response(
            content=resp.content,
            status_code=200,
            media_type=content_type,
            headers={"Cache-Control": "no-store"},
        )
