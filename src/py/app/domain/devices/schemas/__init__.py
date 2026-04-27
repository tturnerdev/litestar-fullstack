"""Devices domain schemas."""

from app.domain.devices.schemas._device import (
    Device,
    DeviceCreate,
    DeviceLineAssignment,
    DeviceUpdate,
)
from app.lib.schema import Message

__all__ = (
    "Device",
    "DeviceCreate",
    "DeviceLineAssignment",
    "DeviceUpdate",
    "Message",
)
