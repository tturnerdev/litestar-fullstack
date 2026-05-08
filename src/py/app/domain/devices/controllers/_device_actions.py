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
from app.domain.devices.jobs import device_reboot_job, device_reprovision_job
from app.domain.devices.schemas import (
    Device,
    DeviceActionResponse,
    DeviceLineAssignment,
    SetDeviceLinesRequest,
)
from app.domain.tasks.deps import provide_background_tasks_service
from app.domain.tasks.schemas import BackgroundTaskDetail
from app.lib.audit import capture_snapshot, log_audit

if TYPE_CHECKING:
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService
    from app.domain.devices.services import DeviceService
    from app.domain.tasks.services import BackgroundTaskService

logger = logging.getLogger(__name__)


def _validate_device_ip(device: m.Device) -> str:
    if not device.ip_address:
        raise NotFoundException(detail="Device has no IP address configured.")
    try:
        addr = ipaddress.ip_address(device.ip_address)
        if not addr.is_private:
            raise ValidationException(detail="Only private/LAN IP addresses are allowed.")
    except ValueError as exc:
        raise ValidationException(detail="Invalid device IP address.") from exc
    return device.ip_address


def _get_phone_auth(device: m.Device) -> tuple[str, str]:
    phone_auth = (device.config_json or {}).get("phoneAuth", {})
    return phone_auth.get("username", "admin"), phone_auth.get("password", "admin")


class DeviceActionsController(Controller):
    """Device action and line assignment endpoints."""

    tags = ["Devices"]
    dependencies = {
        "devices_service": Provide(provide_devices_service),
        "audit_service": Provide(provide_audit_log_service),
        "task_service": Provide(provide_background_tasks_service),
    }

    @post(operation_id="RebootDevice", path="/api/devices/{device_id:uuid}/reboot")
    async def reboot_device(
        self,
        request: Request[m.User, Token, Any],
        devices_service: DeviceService,
        audit_service: AuditLogService,
        task_service: BackgroundTaskService,
        current_user: m.User,
        device_id: Annotated[UUID, Parameter(title="Device ID", description="The device to reboot.")],
    ) -> BackgroundTaskDetail:
        device = await devices_service.get(device_id)
        team_id = device.team_id or (current_user.teams[0].team_id if current_user.teams else None)
        if team_id is None:
            raise ValidationException(detail="Device must belong to a team to perform background actions.")
        task = await task_service.enqueue_tracked_task(
            task_type="device.reboot",
            job_function=device_reboot_job,
            team_id=team_id,
            initiated_by_id=request.user.id,
            entity_type="device",
            entity_id=device.id,
            payload={"device_id": str(device.id)},
            timeout=120,
        )
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
        return task_service.to_schema(task, schema_type=BackgroundTaskDetail)

    @post(operation_id="ReprovisionDevice", path="/api/devices/{device_id:uuid}/reprovision")
    async def reprovision_device(
        self,
        request: Request[m.User, Token, Any],
        devices_service: DeviceService,
        audit_service: AuditLogService,
        task_service: BackgroundTaskService,
        current_user: m.User,
        device_id: Annotated[UUID, Parameter(title="Device ID", description="The device to reprovision.")],
    ) -> BackgroundTaskDetail:
        device = await devices_service.get(device_id)
        team_id = device.team_id or (current_user.teams[0].team_id if current_user.teams else None)
        if team_id is None:
            raise ValidationException(detail="Device must belong to a team to perform background actions.")
        task = await task_service.enqueue_tracked_task(
            task_type="device.reprovision",
            job_function=device_reprovision_job,
            team_id=team_id,
            initiated_by_id=request.user.id,
            entity_type="device",
            entity_id=device.id,
            payload={"device_id": str(device.id)},
            timeout=120,
        )
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
        return task_service.to_schema(task, schema_type=BackgroundTaskDetail)

    @get(operation_id="ListDeviceLines", path="/api/devices/{device_id:uuid}/lines")
    async def list_device_lines(
        self,
        devices_service: DeviceService,
        device_id: Annotated[UUID, Parameter(title="Device ID", description="The device to list lines for.")],
    ) -> list[DeviceLineAssignment]:
        device = await devices_service.get(device_id)
        schemas = []
        for line in device.lines:
            schema = devices_service.to_schema(line, schema_type=DeviceLineAssignment)
            devices_service._enrich_line_schema(line, schema)
            schemas.append(schema)
        return schemas

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
        return devices_service.to_schema_enriched(device)

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
    ) -> Response[bytes]:
        device = await devices_service.get(device_id)
        ip = _validate_device_ip(device)
        username, password = _get_phone_auth(device)

        url = f"https://{ip}/servlet?m=mod_action&command=screenshot"
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

    @post(
        operation_id="SendDeviceAction",
        path="/api/devices/{device_id:uuid}/action",
        include_in_schema=False,
    )
    async def send_device_action(
        self,
        devices_service: DeviceService,
        device_id: Annotated[UUID, Parameter(title="Device ID", description="The device to send an action to.")],
        key: Annotated[str, Parameter(query="key", title="Action Key", description="Yealink Action URI key value (e.g. F1, L1, SPEAKER).")],
    ) -> DeviceActionResponse:
        device = await devices_service.get(device_id)
        ip = _validate_device_ip(device)
        username, password = _get_phone_auth(device)

        url = f"https://{ip}/servlet"
        try:
            async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(10.0)) as http:
                resp = await http.get(url, params={"key": key}, auth=(username, password))
                resp.raise_for_status()
        except httpx.TimeoutException:
            return DeviceActionResponse(
                device_id=device.id, action="key_press", status="error",
                message="Device timed out.",
            )
        except httpx.HTTPStatusError as exc:
            return DeviceActionResponse(
                device_id=device.id, action="key_press", status="error",
                message=f"Device returned {exc.response.status_code}.",
            )
        except httpx.HTTPError:
            return DeviceActionResponse(
                device_id=device.id, action="key_press", status="error",
                message="Could not connect to device.",
            )

        return DeviceActionResponse(
            device_id=device.id, action="key_press", status="ok",
            message=f"Sent key={key} to device.",
        )
