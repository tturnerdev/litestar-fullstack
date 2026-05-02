"""Background task tracking model."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from advanced_alchemy.types import DateTimeUTC
from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._background_task_status import BackgroundTaskStatus

if TYPE_CHECKING:
    from app.db.models._team import Team
    from app.db.models._user import User


class BackgroundTask(UUIDv7AuditBase):
    """Tracks background job lifecycle and results.

    Records task type, status, progress, and outcome for async operations.
    """

    __tablename__ = "background_task"
    __table_args__ = (
        Index("ix_background_task_entity", "entity_type", "entity_id"),
        {"comment": "Tracks background job lifecycle and results"},
    )

    task_type: Mapped[str] = mapped_column(String(length=50), nullable=False, index=True)
    """Type of background task (e.g., 'bulk_export', 'bulk_delete', 'provision')."""

    status: Mapped[str] = mapped_column(
        String(length=50),
        default=BackgroundTaskStatus.PENDING,
        nullable=False,
        index=True,
    )
    """Current status of the task."""

    progress: Mapped[int] = mapped_column(default=0, nullable=False)
    """Progress percentage (0-100)."""

    entity_type: Mapped[str | None] = mapped_column(String(length=50), nullable=True, default=None)
    """Type of entity this task operates on (e.g., 'device', 'fax_message')."""

    entity_id: Mapped[UUID | None] = mapped_column(nullable=True, default=None)
    """ID of the entity this task operates on (polymorphic, no FK constraint)."""

    team_id: Mapped[UUID] = mapped_column(
        ForeignKey("team.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    """ID of the team this task belongs to."""

    initiated_by_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("user_account.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    """ID of the user who initiated this task."""

    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True, default=None)
    """Input data for the task."""

    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True, default=None)
    """Output data from the task."""

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    """Error message if the task failed."""

    saq_job_key: Mapped[str | None] = mapped_column(String(length=100), nullable=True, default=None)
    """SAQ job key for correlating with the task queue."""

    started_at: Mapped[datetime | None] = mapped_column(DateTimeUTC(timezone=True), nullable=True, default=None)
    """When the task started executing."""

    completed_at: Mapped[datetime | None] = mapped_column(DateTimeUTC(timezone=True), nullable=True, default=None)
    """When the task finished (successfully or with error)."""

    # Relationships
    team: Mapped[Team] = relationship(lazy="noload", foreign_keys=[team_id])
    initiated_by: Mapped[User | None] = relationship(lazy="joined", foreign_keys=[initiated_by_id])
