"""Background Task Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from litestar import Controller, get, post
from litestar.params import Dependency, Parameter

from app.db import models as m
from app.domain.tasks.guards import requires_task_access
from app.domain.tasks.schemas import BackgroundTaskDetail, BackgroundTaskList
from app.domain.tasks.services import BackgroundTaskService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination


class BackgroundTaskController(Controller):
    """Background Tasks."""

    tags = ["Background Tasks"]
    dependencies = create_service_dependencies(
        BackgroundTaskService,
        key="task_service",
        load=[m.BackgroundTask.initiated_by],
        filters={
            "id_filter": UUID,
            "search": "task_type",
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    )

    @get(
        operation_id="ListTasks",
        path="/api/tasks",
        guards=[requires_task_access],
    )
    async def list_tasks(
        self,
        task_service: BackgroundTaskService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
        task_type: Annotated[str | None, Parameter(title="Task Type", description="Filter by task type.", query="taskType", required=False)] = None,
        status: Annotated[str | None, Parameter(title="Status", description="Filter by status.", query="status", required=False)] = None,
        entity_type: Annotated[str | None, Parameter(title="Entity Type", description="Filter by entity type.", query="entityType", required=False)] = None,
        entity_id: Annotated[UUID | None, Parameter(title="Entity ID", description="Filter by entity ID.", query="entityId", required=False)] = None,
    ) -> OffsetPagination[BackgroundTaskList]:
        """List background tasks with optional filters."""
        extra_filters = []
        if task_type:
            extra_filters.append(m.BackgroundTask.task_type == task_type)
        if status:
            extra_filters.append(m.BackgroundTask.status == status)
        if entity_type:
            extra_filters.append(m.BackgroundTask.entity_type == entity_type)
        if entity_id:
            extra_filters.append(m.BackgroundTask.entity_id == entity_id)
        results, total = await task_service.list_and_count(*filters, *extra_filters)
        return task_service.to_schema(results, total, filters, schema_type=BackgroundTaskList)

    @get(
        operation_id="ListActiveTasks",
        path="/api/tasks/active",
        guards=[requires_task_access],
    )
    async def list_active_tasks(
        self,
        task_service: BackgroundTaskService,
        current_user: m.User,
    ) -> list[BackgroundTaskList]:
        """List the current user's active (pending/running) tasks."""
        tasks = await task_service.list_active_for_user(current_user.id)
        return [task_service.to_schema(t, schema_type=BackgroundTaskList) for t in tasks]

    @get(
        operation_id="GetTask",
        path="/api/tasks/{task_id:uuid}",
        guards=[requires_task_access],
    )
    async def get_task(
        self,
        task_service: BackgroundTaskService,
        task_id: Annotated[UUID, Parameter(title="Task ID", description="The task to retrieve.")],
    ) -> BackgroundTaskDetail:
        """Get background task details."""
        db_obj = await task_service.get(task_id)
        return task_service.to_schema(db_obj, schema_type=BackgroundTaskDetail)

    @post(
        operation_id="CancelTask",
        path="/api/tasks/{task_id:uuid}/cancel",
        guards=[requires_task_access],
    )
    async def cancel_task(
        self,
        task_service: BackgroundTaskService,
        current_user: m.User,
        task_id: Annotated[UUID, Parameter(title="Task ID", description="The task to cancel.")],
    ) -> BackgroundTaskDetail:
        """Cancel a pending or running task."""
        db_obj = await task_service.cancel_task(task_id)
        return task_service.to_schema(db_obj, schema_type=BackgroundTaskDetail)
