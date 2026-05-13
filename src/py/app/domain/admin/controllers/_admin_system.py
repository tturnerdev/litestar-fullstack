"""Admin System Status Controller."""

from __future__ import annotations

import sys
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

import structlog
from litestar import Controller, get
from litestar.datastructures import CacheControlHeader
from sqlalchemy import func, select, text
from sqlalchemy import table as sa_table
from sqlalchemy.exc import SQLAlchemyError

from app.domain.accounts.guards import requires_superuser
from app.domain.admin.schemas._admin_system import (
    AdminSystemStatus,
    DatabasePoolInfo,
    RedisInfo,
    WorkerQueueInfo,
)

if TYPE_CHECKING:
    from litestar import Request
    from litestar.security.jwt import Token
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.db import models as m
    from app.lib.settings import AppSettings

logger = structlog.get_logger()

_process_start_time = time.time()
_process_started_at = datetime.now(UTC)


def _get_saq_queues() -> list[Any]:
    """Get SAQ queue instances from the plugin config.

    Uses ``SAQPlugin.get_queue(name)`` per configured queue rather than
    accessing ``TaskQueues.queues`` directly, which avoids attribute errors
    when the ``TaskQueues`` dataclass wrapping is inconsistent at runtime.

    Returns:
        List of SAQ ``Queue`` objects, or an empty list if none are configured.
    """
    from app.server.plugins import get_saq_plugin

    saq_plugin = get_saq_plugin()
    return [saq_plugin.get_queue(qc.name) for qc in saq_plugin.config.queue_configs]


async def _get_redis_info() -> RedisInfo | None:
    """Retrieve Redis/Valkey server info via the SAQ plugin's queue redis client."""
    try:
        queues = _get_saq_queues()
        if not queues:
            return None
        queue = queues[0]
        if not hasattr(queue, "redis"):
            return None
        info = await queue.redis.info()
        return RedisInfo(
            status="online",
            version=info.get("redis_version"),
            used_memory_human=info.get("used_memory_human"),
            connected_clients=info.get("connected_clients"),
            uptime_seconds=info.get("uptime_in_seconds"),
        )
    except Exception:  # noqa: BLE001
        logger.warning("Failed to retrieve Redis info", exc_info=True)
        return RedisInfo(status="offline")


def _get_db_pool_info(db_session: Any) -> DatabasePoolInfo | None:
    """Get database connection pool statistics from the engine."""
    try:
        engine = db_session.get_bind()
        pool = engine.pool
        return DatabasePoolInfo(
            pool_size=pool.size(),
            checked_in=pool.checkedin(),
            checked_out=pool.checkedout(),
            overflow=pool.overflow(),
            max_overflow=pool._max_overflow,  # noqa: SLF001
        )
    except Exception:  # noqa: BLE001
        logger.warning("Failed to retrieve database pool info", exc_info=True)
        return None


async def _get_resource_counts(db_session: Any) -> dict[str, int | None]:
    """Fetch quick count aggregates for key resources."""
    counts: dict[str, int | None] = {
        "total_users": None,
        "total_teams": None,
        "total_devices": None,
        "active_connections": None,
    }
    try:
        for key, table in [
            ("total_users", "user_account"),
            ("total_teams", "team"),
            ("total_devices", "device"),
            ("active_connections", "connection"),
        ]:
            result = await db_session.execute(select(func.count()).select_from(sa_table(table)))
            counts[key] = result.scalar()
    except Exception:  # noqa: BLE001
        logger.warning("Failed to retrieve resource counts from database", exc_info=True)
    return counts


class AdminSystemController(Controller):
    """Admin system status endpoints."""

    tags = ["Admin"]
    path = "/api/admin/system"
    guards = [requires_superuser]

    @get(
        operation_id="GetAdminSystemStatus",
        summary="Get system status",
        description="Returns comprehensive system health information including database and Redis status, connection pool stats, worker queue depths, resource counts, and process uptime. Cached for 1 minute. Requires superuser access.",
        path="/status",
        cache=60,
        cache_control=CacheControlHeader(private=True, max_age=60),
    )
    async def get_system_status(
        self,
        request: Request[m.User, Token, Any],
        db_session: AsyncSession,
        settings: AppSettings,
    ) -> AdminSystemStatus:
        """Get comprehensive system status.

        Args:
            request: Request with authenticated superuser.
            db_session: The database session.
            settings: Application settings.

        Returns:
            System status information.
        """
        db_status: Literal["online", "offline"]
        try:
            await db_session.execute(text("select 1"))
            db_status = "online"
        except SQLAlchemyError:
            db_status = "offline"

        uptime_seconds = time.time() - _process_start_time

        worker_queues: list[WorkerQueueInfo] = []
        try:
            for queue in _get_saq_queues():
                try:
                    info = await queue.info()
                    worker_queues.append(
                        WorkerQueueInfo(
                            name=queue.name,
                            queued=info.get("queued", 0),
                            active=info.get("active", 0),
                            scheduled=info.get("scheduled", 0),
                        )
                    )
                except Exception:  # noqa: BLE001
                    logger.warning("Failed to retrieve info for SAQ queue %s", queue.name, exc_info=True)
                    worker_queues.append(WorkerQueueInfo(name=queue.name))
        except Exception:  # noqa: BLE001
            logger.warning("SAQ plugin not available for system status", exc_info=True)

        # Collect Redis info
        redis_info = await _get_redis_info()

        # Collect database pool info
        database_pool = _get_db_pool_info(db_session)

        # Collect resource counts
        resource_counts = await _get_resource_counts(db_session) if db_status == "online" else {}

        # Get Litestar version
        litestar_version: str | None = None
        try:
            import litestar

            litestar_version = litestar.__version__
        except Exception:  # noqa: BLE001
            logger.warning("Failed to determine Litestar version", exc_info=True)

        # Determine environment label
        environment = "development" if settings.DEBUG else "production"

        return AdminSystemStatus(
            database_status=db_status,
            app_name=settings.NAME,
            app_version=settings.VERSION,
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            uptime_seconds=uptime_seconds,
            started_at=_process_started_at,
            debug_mode=settings.DEBUG,
            worker_queues=worker_queues,
            redis_info=redis_info,
            database_pool=database_pool,
            litestar_version=litestar_version,
            environment=environment,
            total_users=resource_counts.get("total_users"),
            total_teams=resource_counts.get("total_teams"),
            total_devices=resource_counts.get("total_devices"),
            active_connections=resource_counts.get("active_connections"),
        )
