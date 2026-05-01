"""Call Record Controllers."""

from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, Response, get, post
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from sqlalchemy import select

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.analytics.guards import requires_analytics_access
from app.domain.analytics.schemas import CallRecordCreate, CallRecordDetail, CallRecordList
from app.domain.analytics.services import CallRecordService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class CallRecordController(Controller):
    """Call Detail Records."""

    tags = ["Analytics"]
    guards = [requires_analytics_access]
    dependencies = create_service_dependencies(
        CallRecordService,
        key="call_records_service",
        filters={
            "id_filter": UUID,
            "search": "source",
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "call_date",
            "sort_order": "desc",
        },
    ) | {
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(operation_id="ListCallRecords", path="/api/analytics/cdrs")
    async def list_call_records(
        self,
        call_records_service: CallRecordService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
        start_date: Annotated[datetime | None, Parameter(query="startDate", required=False)] = None,
        end_date: Annotated[datetime | None, Parameter(query="endDate", required=False)] = None,
        direction: Annotated[str | None, Parameter(query="direction", required=False)] = None,
        disposition: Annotated[str | None, Parameter(query="disposition", required=False)] = None,
        source: Annotated[str | None, Parameter(query="source", required=False)] = None,
        destination: Annotated[str | None, Parameter(query="destination", required=False)] = None,
        min_duration: Annotated[int | None, Parameter(query="minDuration", required=False)] = None,
        max_duration: Annotated[int | None, Parameter(query="maxDuration", required=False)] = None,
    ) -> OffsetPagination[CallRecordList]:
        """List call detail records with filtering.

        Args:
            call_records_service: CallRecord Service
            current_user: Current User
            filters: Standard filters
            start_date: Filter calls on or after this date
            end_date: Filter calls on or before this date
            direction: Filter by call direction
            disposition: Filter by call disposition
            source: Filter by source (partial match)
            destination: Filter by destination (partial match)
            min_duration: Filter by minimum duration in seconds
            max_duration: Filter by maximum duration in seconds

        Returns:
            OffsetPagination[CallRecordList]
        """
        extra_filters = list(_build_cdr_filters(
            current_user=current_user,
            start_date=start_date,
            end_date=end_date,
            direction=direction,
            disposition=disposition,
            source=source,
            destination=destination,
            min_duration=min_duration,
            max_duration=max_duration,
        ))
        if current_user.is_superuser:
            results, total = await call_records_service.list_and_count(*filters, *extra_filters)
        else:
            user_team_ids = (
                select(m.TeamMember.team_id)
                .where(m.TeamMember.user_id == current_user.id)
                .scalar_subquery()
            )
            results, total = await call_records_service.list_and_count(
                *filters,
                *extra_filters,
                m.CallRecord.team_id.in_(user_team_ids),
            )
        return call_records_service.to_schema(results, total, filters, schema_type=CallRecordList)

    @get(operation_id="GetCallRecord", path="/api/analytics/cdrs/{cdr_id:uuid}")
    async def get_call_record(
        self,
        call_records_service: CallRecordService,
        cdr_id: Annotated[UUID, Parameter(title="CDR ID", description="The call record to retrieve.")],
    ) -> CallRecordDetail:
        """Get details about a call record.

        Args:
            call_records_service: CallRecord Service
            cdr_id: Call Record ID

        Returns:
            CallRecordDetail
        """
        db_obj = await call_records_service.get(cdr_id)
        return call_records_service.to_schema(db_obj, schema_type=CallRecordDetail)

    @post(operation_id="CreateCallRecord", path="/api/analytics/cdrs")
    async def create_call_record(
        self,
        request: Request[m.User, Token, Any],
        call_records_service: CallRecordService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: CallRecordCreate,
    ) -> CallRecordDetail:
        """Create a new call record (manual entry or import).

        Args:
            request: The current request
            call_records_service: CallRecord Service
            audit_service: Audit Log Service
            current_user: Current User
            data: CallRecord Create

        Returns:
            CallRecordDetail
        """
        db_obj = await call_records_service.create(data.to_dict())
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="analytics.cdr_create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="call_record",
            target_id=db_obj.id,
            target_label=f"{db_obj.source} -> {db_obj.destination}",
            before=None,
            after=after,
            request=request,
        )
        return call_records_service.to_schema(db_obj, schema_type=CallRecordDetail)

    @get(operation_id="ExportCallRecords", path="/api/analytics/cdrs/export")
    async def export_call_records(
        self,
        call_records_service: CallRecordService,
        current_user: m.User,
        start_date: Annotated[datetime | None, Parameter(query="startDate", required=False)] = None,
        end_date: Annotated[datetime | None, Parameter(query="endDate", required=False)] = None,
        direction: Annotated[str | None, Parameter(query="direction", required=False)] = None,
        disposition: Annotated[str | None, Parameter(query="disposition", required=False)] = None,
    ) -> Response[bytes]:
        """Export call records as CSV.

        Args:
            call_records_service: CallRecord Service
            current_user: Current User
            start_date: Filter calls on or after this date
            end_date: Filter calls on or before this date
            direction: Filter by call direction
            disposition: Filter by call disposition

        Returns:
            CSV file response
        """
        extra_filters = list(_build_cdr_filters(
            current_user=current_user,
            start_date=start_date,
            end_date=end_date,
            direction=direction,
            disposition=disposition,
        ))
        if current_user.is_superuser:
            results, _ = await call_records_service.list_and_count(*extra_filters)
        else:
            user_team_ids = (
                select(m.TeamMember.team_id)
                .where(m.TeamMember.user_id == current_user.id)
                .scalar_subquery()
            )
            results, _ = await call_records_service.list_and_count(
                *extra_filters,
                m.CallRecord.team_id.in_(user_team_ids),
            )

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Call Date",
            "Source",
            "Destination",
            "Caller ID",
            "Direction",
            "Disposition",
            "Duration (s)",
            "Billable (s)",
            "Cost",
            "Channel",
            "Unique ID",
        ])
        for record in results:
            writer.writerow([
                record.call_date.isoformat() if record.call_date else "",
                record.source,
                record.destination,
                record.caller_id or "",
                record.direction,
                record.disposition,
                record.duration,
                record.billable_seconds,
                str(record.cost) if record.cost is not None else "",
                record.channel or "",
                record.unique_id or "",
            ])

        csv_bytes = output.getvalue().encode("utf-8")
        return Response(
            content=csv_bytes,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=call_records.csv"},
        )


def _build_cdr_filters(
    *,
    current_user: m.User | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    direction: str | None = None,
    disposition: str | None = None,
    source: str | None = None,
    destination: str | None = None,
    min_duration: int | None = None,
    max_duration: int | None = None,
) -> list[Any]:
    """Build SQLAlchemy filter clauses from query parameters.

    Args:
        current_user: The current user (unused but kept for consistency).
        start_date: Filter calls on or after this date.
        end_date: Filter calls on or before this date.
        direction: Filter by call direction.
        disposition: Filter by call disposition.
        source: Filter by source (partial match).
        destination: Filter by destination (partial match).
        min_duration: Minimum duration in seconds.
        max_duration: Maximum duration in seconds.

    Returns:
        List of SQLAlchemy column expressions to use as filters.
    """
    clauses: list[Any] = []
    if start_date is not None:
        clauses.append(m.CallRecord.call_date >= start_date)
    if end_date is not None:
        clauses.append(m.CallRecord.call_date <= end_date)
    if direction is not None:
        clauses.append(m.CallRecord.direction == direction)
    if disposition is not None:
        clauses.append(m.CallRecord.disposition == disposition)
    if source is not None:
        clauses.append(m.CallRecord.source.ilike(f"%{source}%"))
    if destination is not None:
        clauses.append(m.CallRecord.destination.ilike(f"%{destination}%"))
    if min_duration is not None:
        clauses.append(m.CallRecord.duration >= min_duration)
    if max_duration is not None:
        clauses.append(m.CallRecord.duration <= max_duration)
    return clauses
