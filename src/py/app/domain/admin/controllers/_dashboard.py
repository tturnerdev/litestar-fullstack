"""Admin Dashboard Controller."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from advanced_alchemy.filters import LimitOffset
from litestar import Controller, get
from litestar.di import Provide

from app.db import models as m
from app.domain.accounts.deps import provide_users_service
from app.domain.accounts.guards import requires_superuser
from app.domain.admin.deps import provide_audit_log_service
from app.domain.admin.schemas import ActivityLogEntry, AdminTrends, DashboardStats, RecentActivity, TrendPoint
from app.domain.devices.deps import provide_devices_service
from app.domain.support.deps import provide_tickets_service
from app.domain.teams.deps import provide_teams_service
from app.domain.voice.deps import provide_extensions_service
from app.domain.voicemail.deps import provide_voicemail_messages_service

if TYPE_CHECKING:
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.accounts.services import UserService
    from app.domain.admin.services import AuditLogService
    from app.domain.devices.services import DeviceService
    from app.domain.support.services import TicketService
    from app.domain.teams.services import TeamService
    from app.domain.voice.services import ExtensionService
    from app.domain.voicemail.services import VoicemailMessageService


class DashboardController(Controller):
    """Admin dashboard endpoints for system statistics and activity monitoring."""

    tags = ["Admin"]
    path = "/api/admin/dashboard"
    guards = [requires_superuser]
    dependencies = {
        "users_service": Provide(provide_users_service),
        "teams_service": Provide(provide_teams_service),
        "audit_service": Provide(provide_audit_log_service),
        "device_service": Provide(provide_devices_service),
        "extension_service": Provide(provide_extensions_service),
        "ticket_service": Provide(provide_tickets_service),
        "voicemail_message_service": Provide(provide_voicemail_messages_service),
    }

    @get(operation_id="GetDashboardStats", path="/stats")
    async def get_stats(
        self,
        request: Request[m.User, Token, Any],
        users_service: UserService,
        teams_service: TeamService,
        audit_service: AuditLogService,
        device_service: DeviceService,
        extension_service: ExtensionService,
        ticket_service: TicketService,
        voicemail_message_service: VoicemailMessageService,
    ) -> DashboardStats:
        """Get system statistics for admin dashboard.

        Args:
            request: Request with authenticated superuser
            users_service: User service
            teams_service: Team service
            audit_service: Audit log service
            device_service: Device service
            extension_service: Extension service
            ticket_service: Ticket service
            voicemail_message_service: Voicemail message service

        Returns:
            Dashboard statistics
        """
        now = datetime.now(UTC)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=7)

        total_users = await users_service.count()
        active_users = await users_service.count(m.User.is_active.is_(True))
        verified_users = await users_service.count(m.User.is_verified.is_(True))
        new_users_today = await users_service.count(m.User.created_at >= today_start)
        new_users_week = await users_service.count(m.User.created_at >= week_start)

        total_teams = await teams_service.count()

        audit_stats = await audit_service.get_stats(hours=24)
        events_today = audit_stats["total_events"]

        total_devices = await device_service.count()
        devices_online = await device_service.count(m.Device.status == "online")

        total_extensions = await extension_service.count()

        open_tickets = await ticket_service.count(
            m.Ticket.status.in_(["open", "in_progress", "waiting_on_support"]),
        )

        unread_voicemails = await voicemail_message_service.count(
            m.VoicemailMessage.is_read.is_(False),
        )

        return DashboardStats(
            total_users=total_users,
            active_users=active_users,
            verified_users=verified_users,
            total_teams=total_teams,
            new_users_today=new_users_today,
            new_users_week=new_users_week,
            events_today=events_today,
            total_devices=total_devices,
            devices_online=devices_online,
            total_extensions=total_extensions,
            open_tickets=open_tickets,
            unread_voicemails=unread_voicemails,
        )

    @get(operation_id="GetRecentActivity", path="/activity")
    async def get_activity(
        self,
        request: Request[m.User, Token, Any],
        audit_service: AuditLogService,
        hours: int = 24,
        limit: int = 50,
    ) -> RecentActivity:
        """Get recent system activity for admin dashboard.

        Args:
            request: Request with authenticated superuser
            audit_service: Audit log service
            hours: Number of hours to look back (default 24)
            limit: Maximum number of entries (default 50)

        Returns:
            Recent activity list
        """
        cutoff_time = datetime.now(UTC) - timedelta(hours=hours)
        results, total = await audit_service.list_and_count(
            m.AuditLog.created_at >= cutoff_time,
            LimitOffset(limit=limit, offset=0),
            order_by=[m.AuditLog.created_at.desc()],
        )

        items = [
            ActivityLogEntry(
                id=log.id,
                action=log.action,
                actor_email=log.actor_email,
                actor_name=log.actor_name,
                target_label=log.target_label,
                created_at=log.created_at,
            )
            for log in results
        ]

        return RecentActivity(activities=items, total=total)

    @get(operation_id="GetDashboardTrends", path="/trends", summary="Get 7-day trend data for dashboard charts")
    async def get_trends(
        self,
        request: Request[m.User, Token, Any],
        users_service: UserService,
        audit_service: AuditLogService,
    ) -> AdminTrends:
        """Get daily trend data for the last 7 days.

        Args:
            request: Request with authenticated superuser
            users_service: User service
            audit_service: Audit log service

        Returns:
            7-day trend data with daily event and user counts
        """
        now = datetime.now(UTC)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        points: list[TrendPoint] = []

        for days_ago in range(6, -1, -1):
            day_start = today_start - timedelta(days=days_ago)
            day_end = day_start + timedelta(days=1)

            event_count = await audit_service.count(
                m.AuditLog.created_at >= day_start,
                m.AuditLog.created_at < day_end,
            )
            new_user_count = await users_service.count(
                m.User.created_at >= day_start,
                m.User.created_at < day_end,
            )

            points.append(
                TrendPoint(
                    date=day_start.strftime("%b %d"),
                    events=event_count,
                    new_users=new_user_count,
                )
            )

        return AdminTrends(points=points)
