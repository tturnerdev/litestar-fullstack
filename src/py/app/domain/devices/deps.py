"""Device domain dependencies."""

from __future__ import annotations

from app.db import models as m
from app.domain.devices.services import DeviceService
from app.lib.deps import create_service_provider

provide_devices_service = create_service_provider(
    DeviceService,
    load=[m.Device.lines, m.Device.location, m.Device.connection],
    error_messages={"duplicate_key": "This device already exists.", "integrity": "Device operation failed."},
)

__all__ = ("provide_devices_service",)
