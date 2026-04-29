"""Unit tests for NotificationService business logic.

Tests service methods with mocked repositories. Focuses on:
- notify() parameter assembly and delegation to create
- mark_read() delegation to update
- mark_all_read() raw SQL statement construction
- get_unread_count() raw SQL count query
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock, MagicMock, patch
from uuid import uuid4

import pytest

from app.domain.notifications.services import NotificationService

pytestmark = [pytest.mark.anyio, pytest.mark.unit, pytest.mark.services]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_service() -> NotificationService:
    """Create a NotificationService with mocked base-class methods.

    Uses __new__ to skip __init__ (which requires a real session),
    then patches the inherited methods as AsyncMocks so tests can
    assert on business logic without a database.
    """
    svc = NotificationService.__new__(NotificationService)
    svc.create = AsyncMock()
    svc.update = AsyncMock()
    svc.list = AsyncMock(return_value=[])
    svc.get = AsyncMock()
    svc.delete = AsyncMock()
    svc.count = AsyncMock(return_value=0)

    # Mock the repository via the internal attribute (the property is read-only)
    mock_repo = MagicMock()
    mock_repo.session = MagicMock()
    mock_repo.session.execute = AsyncMock()
    mock_repo.session.flush = AsyncMock()
    svc._repository_instance = mock_repo
    return svc


def _make_notification(**overrides) -> Mock:
    """Build a mock Notification instance with sensible defaults."""
    defaults = {
        "id": uuid4(),
        "user_id": uuid4(),
        "title": "Test Notification",
        "message": "Something happened",
        "category": "system",
        "is_read": False,
        "action_url": None,
        "metadata_": None,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }
    defaults.update(overrides)
    notification = Mock()
    for k, v in defaults.items():
        setattr(notification, k, v)
    return notification


# ---------------------------------------------------------------------------
# notify
# ---------------------------------------------------------------------------


class TestNotify:
    """Tests for NotificationService.notify."""

    async def test_notify_creates_notification_with_all_fields(self) -> None:
        """Verify notify passes all fields to create."""
        service = _make_service()
        expected = _make_notification()
        service.create = AsyncMock(return_value=expected)

        user_id = uuid4()
        result = await service.notify(
            user_id=user_id,
            title="New Ticket",
            message="A ticket was assigned to you",
            category="ticket",
            action_url="/tickets/123",
            metadata={"ticket_id": "123"},
        )

        service.create.assert_awaited_once()
        call_data = service.create.call_args[0][0]
        assert call_data["user_id"] == user_id
        assert call_data["title"] == "New Ticket"
        assert call_data["message"] == "A ticket was assigned to you"
        assert call_data["category"] == "ticket"
        assert call_data["action_url"] == "/tickets/123"
        assert call_data["metadata_"] == {"ticket_id": "123"}
        assert result is expected

    async def test_notify_with_minimal_fields(self) -> None:
        """Verify notify works with only required fields."""
        service = _make_service()
        expected = _make_notification()
        service.create = AsyncMock(return_value=expected)

        user_id = uuid4()
        result = await service.notify(
            user_id=user_id,
            title="System Alert",
            message="Maintenance window starting",
            category="system",
        )

        call_data = service.create.call_args[0][0]
        assert call_data["user_id"] == user_id
        assert call_data["title"] == "System Alert"
        assert call_data["message"] == "Maintenance window starting"
        assert call_data["category"] == "system"
        assert call_data["action_url"] is None
        assert call_data["metadata_"] is None
        assert result is expected

    async def test_notify_with_none_optional_fields(self) -> None:
        """Verify None values are passed through for optional fields."""
        service = _make_service()
        service.create = AsyncMock(return_value=_make_notification())

        await service.notify(
            user_id=uuid4(),
            title="Alert",
            message="Body",
            category="device",
            action_url=None,
            metadata=None,
        )

        call_data = service.create.call_args[0][0]
        assert call_data["action_url"] is None
        assert call_data["metadata_"] is None


# ---------------------------------------------------------------------------
# mark_read
# ---------------------------------------------------------------------------


class TestMarkRead:
    """Tests for NotificationService.mark_read."""

    async def test_mark_read_calls_update_with_correct_args(self) -> None:
        """Verify mark_read delegates to update with is_read=True."""
        service = _make_service()
        notification_id = uuid4()
        user_id = uuid4()
        expected = _make_notification(id=notification_id, is_read=True)
        service.update = AsyncMock(return_value=expected)

        result = await service.mark_read(
            notification_id=notification_id,
            user_id=user_id,
        )

        service.update.assert_awaited_once_with(
            item_id=notification_id,
            data={"is_read": True},
        )
        assert result is expected

    async def test_mark_read_returns_updated_notification(self) -> None:
        """Verify the return value comes from update."""
        service = _make_service()
        expected = _make_notification(is_read=True)
        service.update = AsyncMock(return_value=expected)

        result = await service.mark_read(
            notification_id=expected.id,
            user_id=expected.user_id,
        )

        assert result.is_read is True


# ---------------------------------------------------------------------------
# mark_all_read
# ---------------------------------------------------------------------------


class TestMarkAllRead:
    """Tests for NotificationService.mark_all_read."""

    async def test_mark_all_read_executes_update_and_flushes(self) -> None:
        """Verify mark_all_read executes SQL and flushes session."""
        service = _make_service()
        user_id = uuid4()

        await service.mark_all_read(user_id=user_id)

        service.repository.session.execute.assert_awaited_once()
        service.repository.session.flush.assert_awaited_once()

    async def test_mark_all_read_returns_none(self) -> None:
        """Verify mark_all_read returns None."""
        service = _make_service()

        result = await service.mark_all_read(user_id=uuid4())

        assert result is None


# ---------------------------------------------------------------------------
# get_unread_count
# ---------------------------------------------------------------------------


class TestGetUnreadCount:
    """Tests for NotificationService.get_unread_count."""

    async def test_get_unread_count_returns_scalar(self) -> None:
        """Verify get_unread_count returns the scalar result from the query."""
        service = _make_service()
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 7
        service.repository.session.execute = AsyncMock(return_value=mock_result)

        user_id = uuid4()
        result = await service.get_unread_count(user_id=user_id)

        assert result == 7
        service.repository.session.execute.assert_awaited_once()
        mock_result.scalar_one.assert_called_once()

    async def test_get_unread_count_zero(self) -> None:
        """Verify get_unread_count returns zero correctly."""
        service = _make_service()
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 0
        service.repository.session.execute = AsyncMock(return_value=mock_result)

        result = await service.get_unread_count(user_id=uuid4())

        assert result == 0

    async def test_get_unread_count_large_number(self) -> None:
        """Verify get_unread_count handles large counts."""
        service = _make_service()
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 9999
        service.repository.session.execute = AsyncMock(return_value=mock_result)

        result = await service.get_unread_count(user_id=uuid4())

        assert result == 9999
