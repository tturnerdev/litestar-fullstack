"""System domain controllers."""

from app.domain.system.controllers._health import SystemController
from app.domain.system.controllers._search import SearchController
from app.domain.system.controllers._sync import SyncController

__all__ = (
    "SearchController",
    "SyncController",
    "SystemController",
)
