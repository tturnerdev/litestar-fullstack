"""Background task status enum."""

from __future__ import annotations

from enum import StrEnum


class BackgroundTaskStatus(StrEnum):
    """Valid statuses for background tasks."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
