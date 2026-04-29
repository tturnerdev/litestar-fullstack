"""Device domain controllers."""

from app.domain.devices.controllers._device import DeviceController
from app.domain.devices.controllers._device_actions import DeviceActionsController

__all__ = ("DeviceActionsController", "DeviceController")
