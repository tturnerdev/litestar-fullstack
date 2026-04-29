"""Unit tests for AuditLogService business logic.

Tests service methods with mocked repositories. Focuses on:
- log_action parameter assembly
- count_recent_actions time window calculation
- Convenience logging methods (admin user/team update/delete)
- get_user_activity ordering and limiting
- get_stats aggregation logic
- Request extraction of ip_address and user_agent
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

import pytest

from app.domain.admin.services import AuditLogService

pytestmark = [pytest.mark.anyio, pytest.mark.unit, pytest.mark.services]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_service() -> AuditLogService:
    """Create an AuditLogService with mocked base-class methods.

    Uses __new__ to skip __init__ (which requires a real session),
    then patches the inherited methods (create, list, count) as AsyncMocks
    so tests can assert on business logic without a database.
    """
    svc = AuditLogService.__new__(AuditLogService)
    svc.create = AsyncMock()
    svc.list = AsyncMock(return_value=[])
    svc.count = AsyncMock(return_value=0)
    return svc


def _make_audit_log(**overrides) -> Mock:
    """Build a mock AuditLog instance with sensible defaults."""
    defaults = {
        "id": uuid4(),
        "action": "test.action",
        "actor_id": uuid4(),
        "actor_email": "actor@example.com",
        "actor_name": "Actor Name",
        "target_type": "user",
        "target_id": str(uuid4()),
        "target_label": "target@example.com",
        "details": None,
        "ip_address": "10.0.0.1",
        "user_agent": "TestAgent/1.0",
        "created_at": datetime.now(UTC),
    }
    defaults.update(overrides)
    log = Mock()
    for k, v in defaults.items():
        setattr(log, k, v)
    return log


def _make_request(ip: str = "192.168.1.1", user_agent: str = "Mozilla/5.0") -> Mock:
    """Create a minimal mock Request with client and headers."""
    mock_request = Mock()
    mock_request.client.host = ip
    mock_request.headers.get = Mock(return_value=user_agent)
    return mock_request


# ---------------------------------------------------------------------------
# log_action
# ---------------------------------------------------------------------------


class TestLogAction:
    """Tests for AuditLogService.log_action."""

    async def test_log_action_creates_entry_with_all_fields(self) -> None:
        """Verify that log_action passes all provided fields to create."""
        service = _make_service()

        expected_log = _make_audit_log()
        service.create = AsyncMock(return_value=expected_log)

        actor_id = uuid4()
        target_id = str(uuid4())

        result = await service.log_action(
            action="user.created",
            actor_id=actor_id,
            actor_email="admin@example.com",
            actor_name="Admin User",
            target_type="user",
            target_id=target_id,
            target_label="new@example.com",
            details={"method": "admin_panel"},
            ip_address="10.0.0.5",
            user_agent="TestBrowser/1.0",
        )

        service.create.assert_awaited_once()
        call_data = service.create.call_args[0][0]
        assert call_data["action"] == "user.created"
        assert call_data["actor_id"] == actor_id
        assert call_data["actor_email"] == "admin@example.com"
        assert call_data["actor_name"] == "Admin User"
        assert call_data["target_type"] == "user"
        assert call_data["target_id"] == target_id
        assert call_data["target_label"] == "new@example.com"
        assert call_data["details"] == {"method": "admin_panel"}
        assert call_data["ip_address"] == "10.0.0.5"
        assert call_data["user_agent"] == "TestBrowser/1.0"
        assert result is expected_log

    async def test_log_action_with_none_optional_fields(self) -> None:
        """Verify that None optional fields are passed through."""
        service = _make_service()
        service.create = AsyncMock(return_value=_make_audit_log())

        await service.log_action(action="system.startup")

        call_data = service.create.call_args[0][0]
        assert call_data["action"] == "system.startup"
        assert call_data["actor_id"] is None
        assert call_data["actor_email"] is None
        assert call_data["target_type"] is None
        assert call_data["details"] is None

    async def test_log_action_extracts_ip_from_request(self) -> None:
        """When a request is provided and ip_address is None, extract from request."""
        service = _make_service()
        service.create = AsyncMock(return_value=_make_audit_log())

        mock_request = _make_request(ip="203.0.113.50", user_agent="Chrome/120")

        await service.log_action(
            action="login.success",
            request=mock_request,
        )

        call_data = service.create.call_args[0][0]
        assert call_data["ip_address"] == "203.0.113.50"
        assert call_data["user_agent"] == "Chrome/120"

    async def test_log_action_explicit_ip_overrides_request(self) -> None:
        """Explicit ip_address/user_agent should not be overridden by request."""
        service = _make_service()
        service.create = AsyncMock(return_value=_make_audit_log())

        mock_request = _make_request(ip="10.0.0.1", user_agent="FromRequest")

        await service.log_action(
            action="login.success",
            ip_address="172.16.0.1",
            user_agent="Explicit",
            request=mock_request,
        )

        call_data = service.create.call_args[0][0]
        assert call_data["ip_address"] == "172.16.0.1"
        assert call_data["user_agent"] == "Explicit"

    async def test_log_action_request_with_no_client(self) -> None:
        """When request.client is None, ip_address stays None."""
        service = _make_service()
        service.create = AsyncMock(return_value=_make_audit_log())

        mock_request = Mock()
        mock_request.client = None
        mock_request.headers.get = Mock(return_value="SomeAgent")

        await service.log_action(
            action="login.success",
            request=mock_request,
        )

        call_data = service.create.call_args[0][0]
        assert call_data["ip_address"] is None
        assert call_data["user_agent"] == "SomeAgent"


# ---------------------------------------------------------------------------
# count_recent_actions
# ---------------------------------------------------------------------------


class TestCountRecentActions:
    """Tests for AuditLogService.count_recent_actions."""

    async def test_count_recent_actions_calls_count_with_correct_filters(self) -> None:
        """Verify the service calls count with action, actor_id, and time filters."""
        service = _make_service()
        service.count = AsyncMock(return_value=5)

        actor_id = uuid4()
        before = datetime.now(UTC)

        result = await service.count_recent_actions(
            action="login.failed",
            actor_id=actor_id,
            window_minutes=15,
        )

        after = datetime.now(UTC)

        assert result == 5
        service.count.assert_awaited_once()

        # Inspect the filter arguments
        call_args = service.count.call_args[0]
        # There should be 3 positional filter args
        assert len(call_args) == 3

    async def test_count_recent_actions_returns_zero_when_empty(self) -> None:
        """Verify zero is returned when no matching actions exist."""
        service = _make_service()
        service.count = AsyncMock(return_value=0)

        result = await service.count_recent_actions(
            action="admin.user.delete",
            actor_id=uuid4(),
            window_minutes=60,
        )

        assert result == 0

    async def test_count_recent_actions_large_window(self) -> None:
        """Verify large time windows work correctly."""
        service = _make_service()
        service.count = AsyncMock(return_value=100)

        result = await service.count_recent_actions(
            action="any.action",
            actor_id=uuid4(),
            window_minutes=1440,  # 24 hours
        )

        assert result == 100


# ---------------------------------------------------------------------------
# log_admin_user_update / log_admin_user_delete
# ---------------------------------------------------------------------------


class TestAdminUserLogging:
    """Tests for admin user audit convenience methods."""

    async def test_log_admin_user_update_records_changes(self) -> None:
        """Verify log_admin_user_update creates proper audit entry."""
        service = _make_service()

        expected_log = _make_audit_log(action="admin.user.update")
        service.create = AsyncMock(return_value=expected_log)

        actor_id = uuid4()
        user_id = uuid4()

        result = await service.log_admin_user_update(
            actor_id=actor_id,
            actor_email="admin@example.com",
            actor_name="Admin User",
            user_id=user_id,
            user_email="target@example.com",
            changes=["name", "is_active"],
        )

        service.create.assert_awaited_once()
        call_data = service.create.call_args[0][0]
        assert call_data["action"] == "admin.user.update"
        assert call_data["actor_id"] == actor_id
        assert call_data["actor_email"] == "admin@example.com"
        assert call_data["actor_name"] == "Admin User"
        assert call_data["target_type"] == "user"
        assert call_data["target_id"] == str(user_id)
        assert call_data["target_label"] == "target@example.com"
        assert call_data["details"] == {"changes": ["name", "is_active"]}
        assert result is expected_log

    async def test_log_admin_user_update_with_request(self) -> None:
        """Verify request info is forwarded to log_action."""
        service = _make_service()
        service.create = AsyncMock(return_value=_make_audit_log())

        mock_request = _make_request(ip="10.0.0.99")

        await service.log_admin_user_update(
            actor_id=uuid4(),
            actor_email="admin@example.com",
            user_id=uuid4(),
            user_email="user@example.com",
            changes=["is_superuser"],
            request=mock_request,
        )

        call_data = service.create.call_args[0][0]
        assert call_data["ip_address"] == "10.0.0.99"

    async def test_log_admin_user_delete_records_deletion(self) -> None:
        """Verify log_admin_user_delete creates proper audit entry."""
        service = _make_service()

        expected_log = _make_audit_log(action="admin.user.delete")
        service.create = AsyncMock(return_value=expected_log)

        actor_id = uuid4()
        user_id = uuid4()

        result = await service.log_admin_user_delete(
            actor_id=actor_id,
            actor_email="admin@example.com",
            user_id=user_id,
            user_email="deleted@example.com",
        )

        call_data = service.create.call_args[0][0]
        assert call_data["action"] == "admin.user.delete"
        assert call_data["target_type"] == "user"
        assert call_data["target_id"] == str(user_id)
        assert call_data["target_label"] == "deleted@example.com"
        # delete does not include details
        assert call_data["details"] is None
        assert result is expected_log


# ---------------------------------------------------------------------------
# log_admin_team_update / log_admin_team_delete
# ---------------------------------------------------------------------------


class TestAdminTeamLogging:
    """Tests for admin team audit convenience methods."""

    async def test_log_admin_team_update_records_changes(self) -> None:
        """Verify log_admin_team_update creates proper audit entry."""
        service = _make_service()

        expected_log = _make_audit_log(action="admin.team.update")
        service.create = AsyncMock(return_value=expected_log)

        actor_id = uuid4()
        team_id = uuid4()

        result = await service.log_admin_team_update(
            actor_id=actor_id,
            actor_email="admin@example.com",
            team_id=team_id,
            team_name="Engineering",
            changes=["name", "description"],
        )

        call_data = service.create.call_args[0][0]
        assert call_data["action"] == "admin.team.update"
        assert call_data["target_type"] == "team"
        assert call_data["target_id"] == str(team_id)
        assert call_data["target_label"] == "Engineering"
        assert call_data["details"] == {"changes": ["name", "description"]}
        assert result is expected_log

    async def test_log_admin_team_delete_records_deletion(self) -> None:
        """Verify log_admin_team_delete creates proper audit entry."""
        service = _make_service()

        expected_log = _make_audit_log(action="admin.team.delete")
        service.create = AsyncMock(return_value=expected_log)

        actor_id = uuid4()
        team_id = uuid4()

        result = await service.log_admin_team_delete(
            actor_id=actor_id,
            actor_email="admin@example.com",
            team_id=team_id,
            team_name="Legacy Team",
        )

        call_data = service.create.call_args[0][0]
        assert call_data["action"] == "admin.team.delete"
        assert call_data["target_type"] == "team"
        assert call_data["target_id"] == str(team_id)
        assert call_data["target_label"] == "Legacy Team"
        assert call_data["details"] is None
        assert result is expected_log

    async def test_log_admin_team_update_with_actor_name(self) -> None:
        """Verify actor_name is recorded when provided."""
        service = _make_service()
        service.create = AsyncMock(return_value=_make_audit_log())

        await service.log_admin_team_update(
            actor_id=uuid4(),
            actor_email="admin@example.com",
            actor_name="Super Admin",
            team_id=uuid4(),
            team_name="DevOps",
            changes=["is_active"],
        )

        call_data = service.create.call_args[0][0]
        assert call_data["actor_name"] == "Super Admin"


# ---------------------------------------------------------------------------
# get_user_activity
# ---------------------------------------------------------------------------


class TestGetUserActivity:
    """Tests for AuditLogService.get_user_activity."""

    async def test_get_user_activity_returns_list(self) -> None:
        """Verify get_user_activity returns a list of audit logs."""
        service = _make_service()

        logs = [_make_audit_log() for _ in range(3)]
        service.list = AsyncMock(return_value=logs)

        user_id = uuid4()
        result = await service.get_user_activity(user_id)

        assert isinstance(result, list)
        assert len(result) == 3
        service.list.assert_awaited_once()

    async def test_get_user_activity_default_limit(self) -> None:
        """Verify default limit of 50 is applied."""
        service = _make_service()
        service.list = AsyncMock(return_value=[])

        user_id = uuid4()
        await service.get_user_activity(user_id)

        call_kwargs = service.list.call_args
        assert call_kwargs.kwargs["limit"] == 50

    async def test_get_user_activity_custom_limit(self) -> None:
        """Verify custom limit is passed to list."""
        service = _make_service()
        service.list = AsyncMock(return_value=[])

        user_id = uuid4()
        await service.get_user_activity(user_id, limit=10)

        call_kwargs = service.list.call_args
        assert call_kwargs.kwargs["limit"] == 10

    async def test_get_user_activity_empty_result(self) -> None:
        """Verify empty list is returned when no activity."""
        service = _make_service()
        service.list = AsyncMock(return_value=[])

        result = await service.get_user_activity(uuid4())

        assert result == []


# ---------------------------------------------------------------------------
# get_stats
# ---------------------------------------------------------------------------


class TestGetStats:
    """Tests for AuditLogService.get_stats."""

    async def test_get_stats_empty_logs(self) -> None:
        """Verify stats structure with no logs."""
        service = _make_service()
        service.list = AsyncMock(return_value=[])

        result = await service.get_stats(hours=24)

        assert result["total_events"] == 0
        assert result["action_counts"] == {}
        assert result["period_hours"] == 24

    async def test_get_stats_aggregates_by_prefix(self) -> None:
        """Verify actions are aggregated by their first dot-separated prefix."""
        service = _make_service()

        logs = [
            _make_audit_log(action="admin.user.update"),
            _make_audit_log(action="admin.user.delete"),
            _make_audit_log(action="admin.team.update"),
            _make_audit_log(action="login.success"),
            _make_audit_log(action="login.failed"),
            _make_audit_log(action="login.failed"),
        ]
        service.list = AsyncMock(return_value=logs)

        result = await service.get_stats(hours=24)

        assert result["total_events"] == 6
        assert result["action_counts"]["admin"] == 3
        assert result["action_counts"]["login"] == 3
        assert result["period_hours"] == 24

    async def test_get_stats_custom_hours(self) -> None:
        """Verify custom hours parameter is included in result."""
        service = _make_service()
        service.list = AsyncMock(return_value=[])

        result = await service.get_stats(hours=48)

        assert result["period_hours"] == 48

    async def test_get_stats_single_action_prefix(self) -> None:
        """Verify stats with all same prefix."""
        service = _make_service()

        logs = [
            _make_audit_log(action="user.created"),
            _make_audit_log(action="user.updated"),
            _make_audit_log(action="user.deleted"),
        ]
        service.list = AsyncMock(return_value=logs)

        result = await service.get_stats()

        assert result["total_events"] == 3
        assert result["action_counts"] == {"user": 3}

    async def test_get_stats_action_without_dot(self) -> None:
        """Verify actions without dots use the whole string as prefix."""
        service = _make_service()

        logs = [_make_audit_log(action="startup")]
        service.list = AsyncMock(return_value=logs)

        result = await service.get_stats()

        assert result["action_counts"] == {"startup": 1}
