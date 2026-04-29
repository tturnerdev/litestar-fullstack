"""Admin System Status Controller."""

from __future__ import annotations

import sys
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

import structlog
from litestar import Controller, get
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.domain.accounts.guards import requires_superuser
from app.domain.admin.schemas._admin_system import AdminSystemStatus, WorkerQueueInfo

if TYPE_CHECKING:
    from litestar import Request
    from litestar.security.jwt import Token
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.db import models as m
    from app.lib.settings import AppSettings

logger = structlog.get_logger()

_process_start_time = time.time()
_process_started_at = datetime.now(UTC)


class AdminSystemController(Controller):
    """Admin system status endpoints."""

    tags = ["Admin"]
    path = "/api/admin/system"
    guards = [requires_superuser]

    @get(operation_id="GetAdminSystemStatus", path="/status")
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
            from litestar_saq import get_saq_plugin

            saq_plugin = get_saq_plugin(request.app)
            for queue in saq_plugin.get_queues().values():
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
                    worker_queues.append(WorkerQueueInfo(name=queue.name))
        except Exception:  # noqa: BLE001
            await logger.adebug("SAQ plugin not available for system status")

        return AdminSystemStatus(
            database_status=db_status,
            app_name=settings.NAME,
            app_version=settings.VERSION,
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            uptime_seconds=uptime_seconds,
            started_at=_process_started_at,
            debug_mode=settings.DEBUG,
            worker_queues=worker_queues,
        )
