"""Admin Tasks Controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from advanced_alchemy.service.pagination import OffsetPagination
from litestar import Controller, delete, get, post
from litestar.di import Provide
from litestar.params import Dependency, Parameter

from app.db import models as m
from app.domain.accounts.guards import requires_superuser
from app.domain.admin.deps import provide_audit_log_service
from app.domain.admin.schemas import AdminTaskStats, AdminTaskSummary
from app.domain.tasks.schemas import BackgroundTaskDetail
from app.domain.tasks.services import BackgroundTaskService
from app.lib.audit import log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class AdminTasksController(Controller):
    """Admin-level background task management (all teams)."""

    tags = ["Admin"]
    path = "/api/admin/tasks"
    guards = [requires_superuser]
    dependencies = create_service_dependencies(
        BackgroundTaskService,
        key="task_service",
        load=[m.BackgroundTask.initiated_by, m.BackgroundTask.team],
        filters={
            "id_filter": UUID,
            "search": "task_type,entity_type",
            "pagination_type": "limit_offset",
            "pagination_size": 25,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    ) | {
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(operation_id="GetAdminTaskStats", path="/stats")
    async def get_task_stats(
        self,
        task_service: BackgroundTaskService,
    ) -> AdminTaskStats:
        """Get aggregate task statistics."""
        raw = await task_service.get_stats()
        return AdminTaskStats(
            by_status=raw["by_status"],
            avg_duration_seconds=raw["avg_duration_seconds"],
            total_today=raw["total_today"],
            total_this_week=raw["total_this_week"],
        )

    @get(operation_id="AdminListTasks", path="/")
    async def list_tasks(
        self,
        task_service: BackgroundTaskService,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
        task_type: Annotated[str | None, Parameter(title="Task Type", description="Filter by task type.", query="taskType", required=False)] = None,
        status: Annotated[str | None, Parameter(title="Status", description="Filter by status.", query="status", required=False)] = None,
        entity_type: Annotated[str | None, Parameter(title="Entity Type", description="Filter by entity type.", query="entityType", required=False)] = None,
    ) -> OffsetPagination[AdminTaskSummary]:
        """List all background tasks across every team."""
        extra_filters = []
        if task_type:
            extra_filters.append(m.BackgroundTask.task_type == task_type)
        if status:
            extra_filters.append(m.BackgroundTask.status == status)
        if entity_type:
            extra_filters.append(m.BackgroundTask.entity_type == entity_type)
        results, total = await task_service.list_and_count(*filters, *extra_filters)
        limit_offset = next((f for f in filters if hasattr(f, "limit")), None)
        items = [
            AdminTaskSummary(
                id=t.id,
                task_type=t.task_type,
                status=t.status,
                progress=t.progress,
                entity_type=t.entity_type,
                entity_id=t.entity_id,
                initiated_by_name=t.initiated_by.name if t.initiated_by else None,
                team_name=t.team.name if t.team else None,
                team_id=t.team_id,
                saq_job_key=t.saq_job_key,
                started_at=t.started_at,
                completed_at=t.completed_at,
                created_at=t.created_at,
                updated_at=t.updated_at,
            )
            for t in results
        ]
        return OffsetPagination(
            items=items,
            total=total,
            limit=limit_offset.limit if limit_offset else 25,
            offset=limit_offset.offset if limit_offset else 0,
        )

    @post(operation_id="AdminCancelTask", path="/{task_id:uuid}/cancel")
    async def cancel_task(
        self,
        request: Request[m.User, Token, Any],
        task_service: BackgroundTaskService,
        audit_service: AuditLogService,
        task_id: Annotated[UUID, Parameter(title="Task ID", description="The task to cancel.")],
    ) -> BackgroundTaskDetail:
        """Cancel a pending or running task (admin)."""
        existing = await task_service.get(task_id)
        previous_status = existing.status
        db_obj = await task_service.cancel_task(task_id)
        await log_audit(
            audit_service,
            action="admin.task.cancelled",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="background_task",
            target_id=task_id,
            target_label=db_obj.task_type,
            metadata={
                "task_type": db_obj.task_type,
                "previous_status": previous_status,
                "entity_type": db_obj.entity_type,
                "entity_id": str(db_obj.entity_id) if db_obj.entity_id else None,
                "team_id": str(db_obj.team_id),
            },
            request=request,
        )
        return task_service.to_schema(db_obj, schema_type=BackgroundTaskDetail)

    @delete(operation_id="AdminDeleteTask", path="/{task_id:uuid}")
    async def delete_task(
        self,
        request: Request[m.User, Token, Any],
        task_service: BackgroundTaskService,
        audit_service: AuditLogService,
        task_id: Annotated[UUID, Parameter(title="Task ID", description="The task to delete.")],
    ) -> None:
        """Delete a completed/failed/cancelled task (admin)."""
        db_obj = await task_service.get(task_id)
        await task_service.delete(task_id)
        await log_audit(
            audit_service,
            action="admin.task.deleted",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="background_task",
            target_id=task_id,
            target_label=db_obj.task_type,
            metadata={
                "task_type": db_obj.task_type,
                "status": db_obj.status,
                "entity_type": db_obj.entity_type,
                "entity_id": str(db_obj.entity_id) if db_obj.entity_id else None,
                "team_id": str(db_obj.team_id),
            },
            request=request,
        )
