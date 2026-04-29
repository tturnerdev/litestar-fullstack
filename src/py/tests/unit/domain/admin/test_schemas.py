"""Unit tests for admin domain schemas.

Tests data transformation, derived field computation, and schema validation.
Focuses on AdminTeamDetail.__post_init__ which computes member_count and owner_email.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.domain.admin.schemas import (
    ActivityLogEntry,
    AdminTeamDetail,
    AdminTeamSummary,
    AdminTrends,
    AdminUserDetail,
    AdminUserSummary,
    AdminUserUpdate,
    AuditLogEntry,
    DashboardStats,
    RecentActivity,
    TrendPoint,
)
from app.domain.admin.schemas._teams import AdminTeamMember, AdminTeamUpdate
from app.domain.accounts.schemas import User

pytestmark = [pytest.mark.unit]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_member(email: str, role: str = "member", is_owner: bool = False) -> AdminTeamMember:
    """Build an AdminTeamMember with a minimal User schema object."""
    user = User(id=uuid4(), email=email)
    return AdminTeamMember(user=user, role=role, is_owner=is_owner)


# ---------------------------------------------------------------------------
# AdminTeamDetail.__post_init__
# ---------------------------------------------------------------------------


class TestAdminTeamDetailPostInit:
    """Tests for the __post_init__ logic that computes member_count and owner_email."""

    def test_member_count_computed_from_members_list(self) -> None:
        """member_count should equal len(members) after construction."""
        members = [_make_member(f"user{i}@example.com") for i in range(5)]
        now = datetime.now(UTC)

        detail = AdminTeamDetail(
            id=uuid4(),
            name="Engineering",
            slug="engineering",
            created_at=now,
            updated_at=now,
            members=members,
        )

        assert detail.member_count == 5

    def test_member_count_zero_with_no_members(self) -> None:
        """member_count should be 0 when no members provided."""
        now = datetime.now(UTC)

        detail = AdminTeamDetail(
            id=uuid4(),
            name="Empty Team",
            slug="empty-team",
            created_at=now,
            updated_at=now,
            members=[],
        )

        assert detail.member_count == 0

    def test_owner_email_found(self) -> None:
        """owner_email should be set to the owner's email."""
        owner = _make_member("owner@example.com", role="admin", is_owner=True)
        member = _make_member("member@example.com", role="member", is_owner=False)
        now = datetime.now(UTC)

        detail = AdminTeamDetail(
            id=uuid4(),
            name="Team A",
            slug="team-a",
            created_at=now,
            updated_at=now,
            members=[member, owner],
        )

        assert detail.owner_email == "owner@example.com"

    def test_owner_email_none_when_no_owner(self) -> None:
        """owner_email should be None when no member is_owner=True."""
        members = [
            _make_member("m1@example.com", is_owner=False),
            _make_member("m2@example.com", is_owner=False),
        ]
        now = datetime.now(UTC)

        detail = AdminTeamDetail(
            id=uuid4(),
            name="No Owner Team",
            slug="no-owner",
            created_at=now,
            updated_at=now,
            members=members,
        )

        assert detail.owner_email is None

    def test_first_owner_wins_when_multiple(self) -> None:
        """When multiple owners exist, the first one encountered sets owner_email."""
        owner1 = _make_member("owner1@example.com", is_owner=True)
        owner2 = _make_member("owner2@example.com", is_owner=True)
        now = datetime.now(UTC)

        detail = AdminTeamDetail(
            id=uuid4(),
            name="Multi Owner",
            slug="multi-owner",
            created_at=now,
            updated_at=now,
            members=[owner1, owner2],
        )

        assert detail.owner_email == "owner1@example.com"

    def test_member_count_overrides_explicit_value(self) -> None:
        """Even if member_count is provided explicitly, __post_init__ recalculates."""
        members = [_make_member("user@example.com")]
        now = datetime.now(UTC)

        detail = AdminTeamDetail(
            id=uuid4(),
            name="Team",
            slug="team",
            created_at=now,
            updated_at=now,
            members=members,
            member_count=999,  # Explicitly wrong
        )

        assert detail.member_count == 1


# ---------------------------------------------------------------------------
# DashboardStats schema construction
# ---------------------------------------------------------------------------


class TestDashboardStats:
    """Tests for DashboardStats schema construction."""

    def test_dashboard_stats_all_zeros(self) -> None:
        """Verify DashboardStats can be constructed with all zero values."""
        stats = DashboardStats(
            total_users=0,
            active_users=0,
            verified_users=0,
            total_teams=0,
            new_users_today=0,
            new_users_week=0,
            events_today=0,
        )

        assert stats.total_users == 0
        assert stats.events_today == 0

    def test_dashboard_stats_with_values(self) -> None:
        """Verify DashboardStats preserves all values."""
        stats = DashboardStats(
            total_users=150,
            active_users=120,
            verified_users=100,
            total_teams=15,
            new_users_today=5,
            new_users_week=25,
            events_today=300,
        )

        assert stats.total_users == 150
        assert stats.active_users == 120
        assert stats.verified_users == 100
        assert stats.total_teams == 15
        assert stats.new_users_today == 5
        assert stats.new_users_week == 25
        assert stats.events_today == 300


# ---------------------------------------------------------------------------
# AdminTrends / TrendPoint
# ---------------------------------------------------------------------------


class TestAdminTrends:
    """Tests for AdminTrends and TrendPoint schemas."""

    def test_empty_trends(self) -> None:
        """Verify AdminTrends with no data points."""
        trends = AdminTrends(points=[])
        assert trends.points == []

    def test_seven_day_trends(self) -> None:
        """Verify a full 7-day trend dataset."""
        points = [
            TrendPoint(date=f"Apr {20 + i}", events=i * 10, new_users=i)
            for i in range(7)
        ]
        trends = AdminTrends(points=points)

        assert len(trends.points) == 7
        assert trends.points[0].date == "Apr 20"
        assert trends.points[0].events == 0
        assert trends.points[6].events == 60
        assert trends.points[6].new_users == 6


# ---------------------------------------------------------------------------
# RecentActivity / ActivityLogEntry
# ---------------------------------------------------------------------------


class TestRecentActivity:
    """Tests for RecentActivity and ActivityLogEntry schemas."""

    def test_recent_activity_empty(self) -> None:
        """Verify empty activity list."""
        activity = RecentActivity(activities=[], total=0)
        assert activity.activities == []
        assert activity.total == 0

    def test_recent_activity_with_entries(self) -> None:
        """Verify activity list construction."""
        now = datetime.now(UTC)
        entries = [
            ActivityLogEntry(
                id=uuid4(),
                action="user.created",
                created_at=now,
                actor_email="admin@example.com",
                actor_name="Admin",
                target_label="new@example.com",
            ),
            ActivityLogEntry(
                id=uuid4(),
                action="team.deleted",
                created_at=now,
                actor_email="admin@example.com",
            ),
        ]
        activity = RecentActivity(activities=entries, total=2)

        assert len(activity.activities) == 2
        assert activity.total == 2
        assert activity.activities[0].action == "user.created"
        assert activity.activities[1].target_label is None

    def test_activity_log_entry_optional_fields_default_to_none(self) -> None:
        """Verify optional fields default to None."""
        entry = ActivityLogEntry(
            id=uuid4(),
            action="login.success",
            created_at=datetime.now(UTC),
        )

        assert entry.actor_email is None
        assert entry.actor_name is None
        assert entry.target_label is None
        assert entry.ip_address is None


# ---------------------------------------------------------------------------
# AuditLogEntry
# ---------------------------------------------------------------------------


class TestAuditLogEntry:
    """Tests for AuditLogEntry schema."""

    def test_audit_log_entry_all_fields(self) -> None:
        """Verify full AuditLogEntry construction."""
        entry_id = uuid4()
        actor_id = uuid4()
        now = datetime.now(UTC)

        entry = AuditLogEntry(
            id=entry_id,
            action="admin.user.update",
            created_at=now,
            actor_id=actor_id,
            actor_email="admin@example.com",
            actor_name="Admin",
            target_type="user",
            target_id=str(uuid4()),
            target_label="user@example.com",
            details={"changes": ["name"]},
            ip_address="10.0.0.1",
            user_agent="TestAgent",
        )

        assert entry.id == entry_id
        assert entry.action == "admin.user.update"
        assert entry.actor_id == actor_id
        assert entry.details == {"changes": ["name"]}

    def test_audit_log_entry_minimal(self) -> None:
        """Verify AuditLogEntry with only required fields."""
        entry = AuditLogEntry(
            id=uuid4(),
            action="system.startup",
            created_at=datetime.now(UTC),
        )

        assert entry.actor_id is None
        assert entry.actor_email is None
        assert entry.details is None
        assert entry.ip_address is None


# ---------------------------------------------------------------------------
# AdminUserSummary / AdminUserDetail / AdminUserUpdate
# ---------------------------------------------------------------------------


class TestAdminUserSchemas:
    """Tests for admin user schemas."""

    def test_user_summary_defaults(self) -> None:
        """Verify AdminUserSummary default values."""
        summary = AdminUserSummary(
            id=uuid4(),
            email="user@example.com",
            created_at=datetime.now(UTC),
        )

        assert summary.is_active is True
        assert summary.is_superuser is False
        assert summary.is_verified is False
        assert summary.login_count == 0
        assert summary.name is None
        assert summary.username is None

    def test_user_detail_defaults(self) -> None:
        """Verify AdminUserDetail default values."""
        now = datetime.now(UTC)

        detail = AdminUserDetail(
            id=uuid4(),
            email="user@example.com",
            created_at=now,
            updated_at=now,
        )

        assert detail.is_active is True
        assert detail.is_two_factor_enabled is False
        assert detail.has_password is True
        assert detail.roles == []
        assert detail.teams == []
        assert detail.oauth_accounts == []

    def test_user_update_unset_fields(self) -> None:
        """Verify AdminUserUpdate uses UNSET for optional fields."""
        from msgspec import UNSET

        update = AdminUserUpdate()

        assert update.name is UNSET
        assert update.username is UNSET
        assert update.phone is UNSET
        assert update.is_active is UNSET
        assert update.is_superuser is UNSET
        assert update.is_verified is UNSET

    def test_user_update_partial(self) -> None:
        """Verify AdminUserUpdate with partial fields."""
        from msgspec import UNSET

        update = AdminUserUpdate(name="New Name", is_active=False)

        assert update.name == "New Name"
        assert update.is_active is False
        assert update.username is UNSET


# ---------------------------------------------------------------------------
# AdminTeamSummary / AdminTeamUpdate
# ---------------------------------------------------------------------------


class TestAdminTeamSchemas:
    """Tests for admin team schemas."""

    def test_team_summary_defaults(self) -> None:
        """Verify AdminTeamSummary default values."""
        summary = AdminTeamSummary(
            id=uuid4(),
            name="Team X",
            slug="team-x",
            created_at=datetime.now(UTC),
        )

        assert summary.member_count == 0
        assert summary.is_active is True

    def test_team_update_unset_fields(self) -> None:
        """Verify AdminTeamUpdate uses UNSET for optional fields."""
        import msgspec

        update = AdminTeamUpdate()

        assert update.name is msgspec.UNSET
        assert update.description is msgspec.UNSET
        assert update.is_active is msgspec.UNSET

    def test_team_update_partial(self) -> None:
        """Verify AdminTeamUpdate with partial fields."""
        import msgspec

        update = AdminTeamUpdate(name="Renamed Team")

        assert update.name == "Renamed Team"
        assert update.description is msgspec.UNSET
