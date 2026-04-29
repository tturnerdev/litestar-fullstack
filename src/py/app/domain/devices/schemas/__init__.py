"""Devices domain schemas."""

from app.domain.devices.schemas._device import (
    Device,
    DeviceActionResponse,
    DeviceCreate,
    DeviceLineAssignment,
    DeviceLineAssignmentInput,
    DeviceUpdate,
    SetDeviceLinesRequest,
)
from app.lib.schema import Message

__all__ = (
    "Device",
    "DeviceActionResponse",
    "DeviceCreate",
    "DeviceLineAssignment",
    "DeviceLineAssignmentInput",
    "DeviceUpdate",
    "Message",
    "SetDeviceLinesRequest",
)
