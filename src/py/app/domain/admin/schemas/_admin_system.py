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


class RedisInfo(CamelizedBaseStruct, kw_only=True):
    """Redis/Valkey connection information."""

    status: Literal["online", "offline"] = "offline"
    version: str | None = None
    used_memory_human: str | None = None
    connected_clients: int | None = None
    uptime_seconds: int | None = None


class DatabasePoolInfo(CamelizedBaseStruct, kw_only=True):
    """Database connection pool statistics."""

    pool_size: int = 0
    checked_in: int = 0
    checked_out: int = 0
    overflow: int = 0
    max_overflow: int = 0


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
    redis_info: RedisInfo | None = None
    database_pool: DatabasePoolInfo | None = None
    litestar_version: str | None = None
    environment: str | None = None
    total_users: int | None = None
    total_teams: int | None = None
    total_devices: int | None = None
    active_connections: int | None = None
