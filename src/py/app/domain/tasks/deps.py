"""Tasks domain dependencies."""

from __future__ import annotations

from app.db import models as m
from app.domain.tasks.services import BackgroundTaskService
from app.lib.deps import create_service_provider

provide_background_tasks_service = create_service_provider(
    BackgroundTaskService,
    load=[m.BackgroundTask.initiated_by],
    error_messages={"duplicate_key": "This task already exists.", "integrity": "Task operation failed."},
)

__all__ = (
    "provide_background_tasks_service",
)
