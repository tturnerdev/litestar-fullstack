"""Background task schemas."""

from datetime import datetime
from uuid import UUID

from app.lib.schema import CamelizedBaseStruct


class BackgroundTaskList(CamelizedBaseStruct):
    """Background task list view."""

    id: UUID
    task_type: str
    status: str
    progress: int = 0
    entity_type: str | None = None
    entity_id: UUID | None = None
    initiated_by_name: str | None = None
    saq_job_key: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class BackgroundTaskDetail(CamelizedBaseStruct):
    """Background task detail view."""

    id: UUID
    task_type: str
    status: str
    team_id: UUID
    progress: int = 0
    entity_type: str | None = None
    entity_id: UUID | None = None
    initiated_by_id: UUID | None = None
    initiated_by_name: str | None = None
    payload: dict | None = None
    result: dict | None = None
    error_message: str | None = None
    saq_job_key: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
