"""Admin task overview schemas."""

from datetime import datetime
from uuid import UUID

from app.lib.schema import CamelizedBaseStruct


class AdminTaskSummary(CamelizedBaseStruct, kw_only=True):
    """Summary task info for admin lists — includes cross-team fields."""

    id: UUID
    task_type: str
    status: str
    progress: int = 0
    entity_type: str | None = None
    entity_id: UUID | None = None
    initiated_by_name: str | None = None
    team_name: str | None = None
    team_id: UUID | None = None
    saq_job_key: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class AdminTaskStats(CamelizedBaseStruct):
    """Aggregate task statistics for admin overview."""

    by_status: dict[str, int]
    avg_duration_seconds: dict[str, float]
    total_today: int
    total_this_week: int
