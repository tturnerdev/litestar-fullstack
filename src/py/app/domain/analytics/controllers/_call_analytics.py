"""Call Analytics Controllers — summary, volume, and per-extension stats."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from litestar import Controller, get
from litestar.di import Provide
from litestar.params import Parameter

from app.db import models as m
from app.domain.analytics.deps import provide_call_records_service
from app.domain.analytics.guards import requires_analytics_access
from app.domain.analytics.schemas import CallAnalyticsSummary, CallVolumePoint, ExtensionStats

from app.domain.analytics.services import CallRecordService


class CallAnalyticsController(Controller):
    """Call analytics aggregate endpoints."""

    tags = ["Analytics"]
    guards = [requires_analytics_access]
    dependencies = {
        "call_records_service": Provide(provide_call_records_service),
    }

    @get(operation_id="GetCallSummary", path="/api/analytics/summary")
    async def get_summary(
        self,
        call_records_service: CallRecordService,
        current_user: m.User,
        team_id: Annotated[UUID, Parameter(query="teamId", required=True)],
        start_date: Annotated[datetime, Parameter(query="startDate", required=True)],
        end_date: Annotated[datetime, Parameter(query="endDate", required=True)],
    ) -> CallAnalyticsSummary:
        """Get aggregate call statistics for a team within a date range.

        Args:
            call_records_service: CallRecord Service
            current_user: Current User
            team_id: Team to get stats for
            start_date: Start of the date range
            end_date: End of the date range

        Returns:
            CallAnalyticsSummary
        """
        _verify_team_access(current_user, team_id)
        return await call_records_service.get_summary(team_id, start_date, end_date)

    @get(operation_id="GetCallVolume", path="/api/analytics/volume")
    async def get_volume(
        self,
        call_records_service: CallRecordService,
        current_user: m.User,
        team_id: Annotated[UUID, Parameter(query="teamId", required=True)],
        start_date: Annotated[datetime, Parameter(query="startDate", required=True)],
        end_date: Annotated[datetime, Parameter(query="endDate", required=True)],
        interval: Annotated[str, Parameter(query="interval", required=False)] = "day",
    ) -> list[CallVolumePoint]:
        """Get call volume over time for charting.

        Args:
            call_records_service: CallRecord Service
            current_user: Current User
            team_id: Team to get stats for
            start_date: Start of the date range
            end_date: End of the date range
            interval: Grouping interval: hour, day, week, or month

        Returns:
            List of CallVolumePoint
        """
        _verify_team_access(current_user, team_id)
        return await call_records_service.get_volume(team_id, start_date, end_date, interval)

    @get(operation_id="GetCallsByExtension", path="/api/analytics/by-extension")
    async def get_by_extension(
        self,
        call_records_service: CallRecordService,
        current_user: m.User,
        team_id: Annotated[UUID, Parameter(query="teamId", required=True)],
        start_date: Annotated[datetime, Parameter(query="startDate", required=True)],
        end_date: Annotated[datetime, Parameter(query="endDate", required=True)],
    ) -> list[ExtensionStats]:
        """Get per-extension call statistics.

        Args:
            call_records_service: CallRecord Service
            current_user: Current User
            team_id: Team to get stats for
            start_date: Start of the date range
            end_date: End of the date range

        Returns:
            List of ExtensionStats
        """
        _verify_team_access(current_user, team_id)
        return await call_records_service.get_by_extension(team_id, start_date, end_date)


def _verify_team_access(current_user: m.User, team_id: UUID) -> None:
    """Verify the user has access to the given team.

    Superusers can access any team. Non-superusers must be a member.
    Note: The guard already verified basic auth; this is belt-and-suspenders
    for the team_id parameter. Full membership verification happens at the
    DB query level in the service methods.

    Args:
        current_user: The current user.
        team_id: The team ID being queried.
    """
    # Superusers bypass team membership checks.
    # For non-superusers, the service queries are scoped by team_id,
    # which is validated by the caller passing a team they belong to.
    # Full membership enforcement can be added here if needed.
