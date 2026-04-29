"""System domain controllers."""

from app.domain.system.controllers._health import SystemController
from app.domain.system.controllers._sync import SyncController

__all__ = (
    "SyncController",
    "SystemController",
)
