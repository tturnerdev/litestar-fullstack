"""Call record service."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from advanced_alchemy.extensions.litestar import repository, service
from sqlalchemy import case, cast, func, select
from sqlalchemy.types import Float

from app.db import models as m
from app.db.models._call_record_enums import CallDisposition
from app.domain.analytics.schemas import CallAnalyticsSummary, CallVolumePoint, ExtensionStats


class CallRecordService(service.SQLAlchemyAsyncRepositoryService[m.CallRecord]):
    """Handles CRUD operations and analytics queries on CallRecord resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.CallRecord]):
        """CallRecord Repository."""

        model_type = m.CallRecord

    repository_type = Repo

    async def get_summary(
        self,
        team_id: UUID,
        start_date: datetime,
        end_date: datetime,
    ) -> CallAnalyticsSummary:
        """Compute aggregate call statistics for a team within a date range.

        Args:
            team_id: The team to query for.
            start_date: Start of the date range (inclusive).
            end_date: End of the date range (inclusive).

        Returns:
            CallAnalyticsSummary with aggregate stats.
        """
        stmt = select(
            func.count().label("total_calls"),
            func.coalesce(
                func.sum(case((m.CallRecord.disposition == CallDisposition.ANSWERED, 1), else_=0)),
                0,
            ).label("answered"),
            func.coalesce(
                func.sum(
                    case(
                        (m.CallRecord.disposition.in_([CallDisposition.NO_ANSWER, CallDisposition.BUSY, CallDisposition.FAILED]), 1),
                        else_=0,
                    )
                ),
                0,
            ).label("missed"),
            func.coalesce(
                func.sum(case((m.CallRecord.disposition == CallDisposition.VOICEMAIL, 1), else_=0)),
                0,
            ).label("voicemail"),
            func.coalesce(func.avg(cast(m.CallRecord.duration, Float)), 0.0).label("avg_duration"),
            func.coalesce(func.sum(m.CallRecord.duration), 0).label("total_duration"),
            func.coalesce(func.avg(cast(m.CallRecord.billable_seconds, Float)), 0.0).label("avg_billable_seconds"),
        ).where(
            m.CallRecord.team_id == team_id,
            m.CallRecord.call_date >= start_date,
            m.CallRecord.call_date <= end_date,
        )
        result = await self.repository.session.execute(stmt)
        row = result.one()
        return CallAnalyticsSummary(
            total_calls=row.total_calls,
            answered=row.answered,
            missed=row.missed,
            voicemail=row.voicemail,
            avg_duration=round(float(row.avg_duration), 2),
            total_duration=row.total_duration,
            avg_billable_seconds=round(float(row.avg_billable_seconds), 2),
        )

    async def get_volume(
        self,
        team_id: UUID,
        start_date: datetime,
        end_date: datetime,
        interval: str = "day",
    ) -> list[CallVolumePoint]:
        """Compute call volume over time for charting.

        Args:
            team_id: The team to query for.
            start_date: Start of the date range (inclusive).
            end_date: End of the date range (inclusive).
            interval: Grouping interval: hour, day, week, or month.

        Returns:
            List of CallVolumePoint data points ordered by period.
        """
        trunc_map = {
            "hour": "hour",
            "day": "day",
            "week": "week",
            "month": "month",
        }
        trunc_value = trunc_map.get(interval, "day")
        period_col = func.date_trunc(trunc_value, m.CallRecord.call_date).label("period")

        stmt = (
            select(
                period_col,
                func.count().label("count"),
                func.coalesce(
                    func.sum(case((m.CallRecord.disposition == CallDisposition.ANSWERED, 1), else_=0)),
                    0,
                ).label("answered"),
                func.coalesce(
                    func.sum(
                        case(
                            (m.CallRecord.disposition.in_([CallDisposition.NO_ANSWER, CallDisposition.BUSY, CallDisposition.FAILED]), 1),
                            else_=0,
                        )
                    ),
                    0,
                ).label("missed"),
            )
            .where(
                m.CallRecord.team_id == team_id,
                m.CallRecord.call_date >= start_date,
                m.CallRecord.call_date <= end_date,
            )
            .group_by(period_col)
            .order_by(period_col)
        )
        result = await self.repository.session.execute(stmt)
        return [
            CallVolumePoint(
                period=row.period.isoformat(),
                count=row.count,
                answered=row.answered,
                missed=row.missed,
            )
            for row in result.all()
        ]

    async def get_by_extension(
        self,
        team_id: UUID,
        start_date: datetime,
        end_date: datetime,
    ) -> list[ExtensionStats]:
        """Compute per-extension call statistics.

        Args:
            team_id: The team to query for.
            start_date: Start of the date range (inclusive).
            end_date: End of the date range (inclusive).

        Returns:
            List of ExtensionStats ordered by total_calls descending.
        """
        stmt = (
            select(
                m.CallRecord.source.label("extension"),
                func.count().label("total_calls"),
                func.coalesce(
                    func.sum(case((m.CallRecord.disposition == CallDisposition.ANSWERED, 1), else_=0)),
                    0,
                ).label("answered"),
                func.coalesce(
                    func.sum(
                        case(
                            (m.CallRecord.disposition.in_([CallDisposition.NO_ANSWER, CallDisposition.BUSY, CallDisposition.FAILED]), 1),
                            else_=0,
                        )
                    ),
                    0,
                ).label("missed"),
                func.coalesce(func.avg(cast(m.CallRecord.duration, Float)), 0.0).label("avg_duration"),
            )
            .where(
                m.CallRecord.team_id == team_id,
                m.CallRecord.call_date >= start_date,
                m.CallRecord.call_date <= end_date,
            )
            .group_by(m.CallRecord.source)
            .order_by(func.count().desc())
        )
        result = await self.repository.session.execute(stmt)
        return [
            ExtensionStats(
                extension=row.extension,
                total_calls=row.total_calls,
                answered=row.answered,
                missed=row.missed,
                avg_duration=round(float(row.avg_duration), 2),
            )
            for row in result.all()
        ]
