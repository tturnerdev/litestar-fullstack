"""Schedule Controllers."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.schedules.deps import provide_schedule_entries_service
from app.domain.schedules.guards import requires_schedule_team_membership
from app.domain.schedules.schemas import (
    ScheduleCheckResponse,
    ScheduleCreate,
    ScheduleDetail,
    ScheduleEntryCreate,
    ScheduleEntryDetail,
    ScheduleEntryList,
    ScheduleEntryUpdate,
    ScheduleList,
    ScheduleUpdate,
)
from app.domain.schedules.services import ScheduleEntryService, ScheduleService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class ScheduleController(Controller):
    """Schedules."""

    tags = ["Schedules"]
    dependencies = create_service_dependencies(
        ScheduleService,
        key="schedules_service",
        load=[selectinload(m.Schedule.entries)],
        filters={
            "id_filter": UUID,
            "search": "name",
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "name",
            "sort_order": "asc",
        },
    ) | {
        "audit_service": Provide(provide_audit_log_service),
        "entries_service": Provide(provide_schedule_entries_service),
    }

    # ── Schedule CRUD ──────────────────────────────────────────────────

    @get(operation_id="ListSchedules", path="/api/schedules")
    async def list_schedules(
        self,
        schedules_service: ScheduleService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
        team_id: Annotated[UUID | None, Parameter(title="Team ID", description="Filter by team.", required=False)] = None,
        schedule_type: Annotated[str | None, Parameter(title="Schedule Type", description="Filter by schedule type.", required=False)] = None,
    ) -> OffsetPagination[ScheduleList]:
        """List schedules.

        Args:
            schedules_service: Schedule Service
            current_user: Current User
            filters: Filters
            team_id: Optional team filter
            schedule_type: Optional schedule type filter

        Returns:
            OffsetPagination[ScheduleList]
        """
        extra_filters: list[Any] = []
        if team_id:
            extra_filters.append(m.Schedule.team_id == team_id)
        if schedule_type:
            extra_filters.append(m.Schedule.schedule_type == schedule_type)
        results, total = await schedules_service.list_and_count(*filters, *extra_filters)
        return schedules_service.to_schema(results, total, filters, schema_type=ScheduleList)

    @post(operation_id="CreateSchedule", path="/api/schedules")
    async def create_schedule(
        self,
        request: Request[m.User, Token, Any],
        schedules_service: ScheduleService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: ScheduleCreate,
    ) -> ScheduleDetail:
        """Create a new schedule.

        Args:
            request: The current request
            schedules_service: Schedule Service
            audit_service: Audit Log Service
            current_user: Current User
            data: Schedule Create

        Returns:
            ScheduleDetail
        """
        obj = data.to_dict()
        db_obj = await schedules_service.create(obj)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="schedule.create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="schedule",
            target_id=db_obj.id,
            target_label=db_obj.name,
            before=None,
            after=after,
            request=request,
        )
        return schedules_service.to_schema(db_obj, schema_type=ScheduleDetail)

    @get(
        operation_id="GetSchedule",
        path="/api/schedules/{schedule_id:uuid}",
    )
    async def get_schedule(
        self,
        schedules_service: ScheduleService,
        schedule_id: Annotated[UUID, Parameter(title="Schedule ID", description="The schedule to retrieve.")],
    ) -> ScheduleDetail:
        """Get details about a schedule.

        Args:
            schedules_service: Schedule Service
            schedule_id: Schedule ID

        Returns:
            ScheduleDetail
        """
        db_obj = await schedules_service.get(schedule_id)
        return schedules_service.to_schema(db_obj, schema_type=ScheduleDetail)

    @patch(
        operation_id="UpdateSchedule",
        path="/api/schedules/{schedule_id:uuid}",
    )
    async def update_schedule(
        self,
        request: Request[m.User, Token, Any],
        data: ScheduleUpdate,
        schedules_service: ScheduleService,
        audit_service: AuditLogService,
        current_user: m.User,
        schedule_id: Annotated[UUID, Parameter(title="Schedule ID", description="The schedule to update.")],
    ) -> ScheduleDetail:
        """Update a schedule.

        Args:
            request: The current request
            data: Schedule Update
            schedules_service: Schedule Service
            audit_service: Audit Log Service
            current_user: Current User
            schedule_id: Schedule ID

        Returns:
            ScheduleDetail
        """
        before = capture_snapshot(await schedules_service.get(schedule_id))
        await schedules_service.update(
            item_id=schedule_id,
            data=data.to_dict(),
        )
        fresh_obj = await schedules_service.get_one(id=schedule_id)
        after = capture_snapshot(fresh_obj)
        await log_audit(
            audit_service,
            action="schedule.update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="schedule",
            target_id=schedule_id,
            target_label=fresh_obj.name,
            before=before,
            after=after,
            request=request,
        )
        return schedules_service.to_schema(fresh_obj, schema_type=ScheduleDetail)

    @delete(
        operation_id="DeleteSchedule",
        path="/api/schedules/{schedule_id:uuid}",
    )
    async def delete_schedule(
        self,
        request: Request[m.User, Token, Any],
        schedules_service: ScheduleService,
        audit_service: AuditLogService,
        current_user: m.User,
        schedule_id: Annotated[UUID, Parameter(title="Schedule ID", description="The schedule to delete.")],
    ) -> None:
        """Delete a schedule.

        Args:
            request: The current request
            schedules_service: Schedule Service
            audit_service: Audit Log Service
            current_user: Current User
            schedule_id: Schedule ID
        """
        db_obj = await schedules_service.get(schedule_id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.name
        await schedules_service.delete(schedule_id)
        await log_audit(
            audit_service,
            action="schedule.delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="schedule",
            target_id=schedule_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )

    # ── Schedule Check ─────────────────────────────────────────────────

    @get(
        operation_id="CheckSchedule",
        path="/api/schedules/{schedule_id:uuid}/check",
    )
    async def check_schedule(
        self,
        schedules_service: ScheduleService,
        schedule_id: Annotated[UUID, Parameter(title="Schedule ID", description="The schedule to check.")],
        time: Annotated[datetime | None, Parameter(title="Check Time", description="ISO datetime to check (defaults to now).", required=False)] = None,
    ) -> ScheduleCheckResponse:
        """Check whether a schedule is open or closed at a given time.

        Args:
            schedules_service: Schedule Service
            schedule_id: Schedule ID
            time: Optional check time (defaults to now in the schedule's timezone)

        Returns:
            ScheduleCheckResponse
        """
        return await schedules_service.check_schedule(schedule_id, check_time=time)

    # ── Schedule Entry CRUD ────────────────────────────────────────────

    @get(
        operation_id="ListScheduleEntries",
        path="/api/schedules/{schedule_id:uuid}/entries",
    )
    async def list_entries(
        self,
        entries_service: ScheduleEntryService,
        schedule_id: Annotated[UUID, Parameter(title="Schedule ID", description="The schedule to list entries for.")],
    ) -> list[ScheduleEntryList]:
        """List entries for a schedule.

        Args:
            entries_service: Schedule Entry Service
            schedule_id: Schedule ID

        Returns:
            list[ScheduleEntryList]
        """
        results = await entries_service.list(m.ScheduleEntry.schedule_id == schedule_id)
        return entries_service.to_schema(results, schema_type=ScheduleEntryList)

    @post(
        operation_id="CreateScheduleEntry",
        path="/api/schedules/{schedule_id:uuid}/entries",
    )
    async def create_entry(
        self,
        request: Request[m.User, Token, Any],
        entries_service: ScheduleEntryService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: ScheduleEntryCreate,
        schedule_id: Annotated[UUID, Parameter(title="Schedule ID", description="The schedule to create the entry for.")],
    ) -> ScheduleEntryDetail:
        """Create a new entry in a schedule.

        Args:
            request: The current request
            entries_service: Schedule Entry Service
            audit_service: Audit Log Service
            current_user: Current User
            data: Schedule Entry Create
            schedule_id: Schedule ID

        Returns:
            ScheduleEntryDetail
        """
        obj = data.to_dict()
        obj["schedule_id"] = schedule_id
        db_obj = await entries_service.create(obj)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="schedule_entry.create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="schedule_entry",
            target_id=db_obj.id,
            target_label=db_obj.label or f"Entry {db_obj.id}",
            before=None,
            after=after,
            request=request,
        )
        return entries_service.to_schema(db_obj, schema_type=ScheduleEntryDetail)

    @patch(
        operation_id="UpdateScheduleEntry",
        path="/api/schedules/{schedule_id:uuid}/entries/{entry_id:uuid}",
    )
    async def update_entry(
        self,
        request: Request[m.User, Token, Any],
        data: ScheduleEntryUpdate,
        entries_service: ScheduleEntryService,
        audit_service: AuditLogService,
        current_user: m.User,
        schedule_id: Annotated[UUID, Parameter(title="Schedule ID", description="The schedule the entry belongs to.")],
        entry_id: Annotated[UUID, Parameter(title="Entry ID", description="The entry to update.")],
    ) -> ScheduleEntryDetail:
        """Update a schedule entry.

        Args:
            request: The current request
            data: Schedule Entry Update
            entries_service: Schedule Entry Service
            audit_service: Audit Log Service
            current_user: Current User
            schedule_id: Schedule ID
            entry_id: Entry ID

        Returns:
            ScheduleEntryDetail
        """
        before = capture_snapshot(await entries_service.get(entry_id))
        await entries_service.update(
            item_id=entry_id,
            data=data.to_dict(),
        )
        fresh_obj = await entries_service.get_one(id=entry_id)
        after = capture_snapshot(fresh_obj)
        await log_audit(
            audit_service,
            action="schedule_entry.update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="schedule_entry",
            target_id=entry_id,
            target_label=fresh_obj.label or f"Entry {entry_id}",
            before=before,
            after=after,
            request=request,
        )
        return entries_service.to_schema(fresh_obj, schema_type=ScheduleEntryDetail)

    @delete(
        operation_id="DeleteScheduleEntry",
        path="/api/schedules/{schedule_id:uuid}/entries/{entry_id:uuid}",
    )
    async def delete_entry(
        self,
        request: Request[m.User, Token, Any],
        entries_service: ScheduleEntryService,
        audit_service: AuditLogService,
        current_user: m.User,
        schedule_id: Annotated[UUID, Parameter(title="Schedule ID", description="The schedule the entry belongs to.")],
        entry_id: Annotated[UUID, Parameter(title="Entry ID", description="The entry to delete.")],
    ) -> None:
        """Delete a schedule entry.

        Args:
            request: The current request
            entries_service: Schedule Entry Service
            audit_service: Audit Log Service
            current_user: Current User
            schedule_id: Schedule ID
            entry_id: Entry ID
        """
        db_obj = await entries_service.get(entry_id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.label or f"Entry {entry_id}"
        await entries_service.delete(entry_id)
        await log_audit(
            audit_service,
            action="schedule_entry.delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="schedule_entry",
            target_id=entry_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )
