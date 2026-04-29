"""Admin system status schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from app.lib.schema import CamelizedBaseStruct


class WorkerQueueInfo(CamelizedBaseStruct, kw_only=True):
    """Worker queue status information."""

    name: str
    queued: int = 0
    active: int = 0
    scheduled: int = 0


class AdminSystemStatus(CamelizedBaseStruct, kw_only=True):
    """Comprehensive system status for admin dashboard."""

    database_status: Literal["online", "offline"]
    app_name: str
    app_version: str
    python_version: str
    uptime_seconds: float
    started_at: datetime
    debug_mode: bool
    worker_queues: list[WorkerQueueInfo] = []
