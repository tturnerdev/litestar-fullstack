"""Unit tests for NotificationPreferenceService business logic.

Tests service methods with mocked repositories. Focuses on:
- get_or_create_for_user() returns existing or creates defaults
- update_for_user() merges categories, validates keys, creates if needed
- is_category_enabled() checks email_enabled + category
"""

from __future__ import annotations

from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

from app.db.models._notification_preference import DEFAULT_CATEGORIES
from app.domain.notifications.services import NotificationPreferenceService

pytestmark = [pytest.mark.anyio, pytest.mark.unit, pytest.mark.services]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_service() -> NotificationPreferenceService:
    """Create a NotificationPreferenceService with mocked base-class methods.

    Uses __new__ to skip __init__ (which requires a real session),
    then patches the inherited methods as AsyncMocks.
    """
    svc = NotificationPreferenceService.__new__(NotificationPreferenceService)
    svc.create = AsyncMock()
    svc.update = AsyncMock()
    svc.get_one_or_none = AsyncMock(return_value=None)
    svc.list = AsyncMock(return_value=[])
    svc.get = AsyncMock()
    svc.delete = AsyncMock()
    return svc


def _make_preference(**overrides) -> Mock:
    """Build a mock NotificationPreference with sensible defaults."""
    defaults = {
        "id": uuid4(),
        "user_id": uuid4(),
        "email_enabled": True,
        "categories": dict(DEFAULT_CATEGORIES),
    }
    defaults.update(overrides)
    pref = Mock()
    for k, v in defaults.items():
        setattr(pref, k, v)
    return pref


# ---------------------------------------------------------------------------
# get_or_create_for_user
# ---------------------------------------------------------------------------


class TestGetOrCreateForUser:
    """Tests for NotificationPreferenceService.get_or_create_for_user."""

    async def test_returns_existing_preference(self) -> None:
        """When a preference exists, return it without creating."""
        service = _make_service()
        user_id = uuid4()
        existing = _make_preference(user_id=user_id)
        service.get_one_or_none = AsyncMock(return_value=existing)

        result = await service.get_or_create_for_user(user_id=user_id)

        assert result is existing
        service.create.assert_not_awaited()

    async def test_creates_defaults_when_none_exists(self) -> None:
        """When no preference exists, create one with defaults."""
        service = _make_service()
        user_id = uuid4()
        service.get_one_or_none = AsyncMock(return_value=None)
        created = _make_preference(user_id=user_id)
        service.create = AsyncMock(return_value=created)

        result = await service.get_or_create_for_user(user_id=user_id)

        service.create.assert_awaited_once()
        call_data = service.create.call_args[1]["data"]
        assert call_data["user_id"] == user_id
        assert call_data["email_enabled"] is True
        assert call_data["categories"] == dict(DEFAULT_CATEGORIES)
        assert result is created

    async def test_creates_with_all_default_categories(self) -> None:
        """Verify the created preference includes every default category."""
        service = _make_service()
        service.get_one_or_none = AsyncMock(return_value=None)
        service.create = AsyncMock(return_value=_make_preference())

        await service.get_or_create_for_user(user_id=uuid4())

        call_data = service.create.call_args[1]["data"]
        for cat_key in DEFAULT_CATEGORIES:
            assert cat_key in call_data["categories"]
            assert call_data["categories"][cat_key] is True


# ---------------------------------------------------------------------------
# update_for_user
# ---------------------------------------------------------------------------


class TestUpdateForUser:
    """Tests for NotificationPreferenceService.update_for_user."""

    async def test_update_email_enabled(self) -> None:
        """Verify updating email_enabled field."""
        service = _make_service()
        user_id = uuid4()
        pref = _make_preference(user_id=user_id, email_enabled=True)
        service.get_one_or_none = AsyncMock(return_value=pref)
        updated_pref = _make_preference(user_id=user_id, email_enabled=False)
        service.update = AsyncMock(return_value=updated_pref)

        result = await service.update_for_user(
            user_id=user_id,
            data={"email_enabled": False},
        )

        service.update.assert_awaited_once()
        call_kwargs = service.update.call_args[1]
        assert call_kwargs["item_id"] == pref.id
        assert call_kwargs["data"]["email_enabled"] is False

    async def test_update_merges_categories(self) -> None:
        """Verify categories are merged with existing values."""
        service = _make_service()
        user_id = uuid4()
        existing_categories = dict(DEFAULT_CATEGORIES)
        pref = _make_preference(user_id=user_id, categories=existing_categories)
        service.get_one_or_none = AsyncMock(return_value=pref)
        service.update = AsyncMock(return_value=pref)

        await service.update_for_user(
            user_id=user_id,
            data={"categories": {"teams": False, "fax": False}},
        )

        call_kwargs = service.update.call_args[1]
        merged = call_kwargs["data"]["categories"]
        # Updated values should be False
        assert merged["teams"] is False
        assert merged["fax"] is False
        # Untouched values stay True
        assert merged["devices"] is True
        assert merged["voice"] is True
        assert merged["support"] is True
        assert merged["system"] is True

    async def test_update_ignores_invalid_category_keys(self) -> None:
        """Verify unknown category keys are filtered out."""
        service = _make_service()
        user_id = uuid4()
        pref = _make_preference(user_id=user_id, categories=dict(DEFAULT_CATEGORIES))
        service.get_one_or_none = AsyncMock(return_value=pref)
        service.update = AsyncMock(return_value=pref)

        await service.update_for_user(
            user_id=user_id,
            data={"categories": {"bogus_category": True, "teams": False}},
        )

        call_kwargs = service.update.call_args[1]
        merged = call_kwargs["data"]["categories"]
        assert "bogus_category" not in merged
        assert merged["teams"] is False

    async def test_update_ignores_non_bool_category_values(self) -> None:
        """Verify non-bool values in categories are filtered out."""
        service = _make_service()
        user_id = uuid4()
        pref = _make_preference(user_id=user_id, categories=dict(DEFAULT_CATEGORIES))
        service.get_one_or_none = AsyncMock(return_value=pref)
        service.update = AsyncMock(return_value=pref)

        await service.update_for_user(
            user_id=user_id,
            data={"categories": {"teams": "not_a_bool", "fax": False}},
        )

        call_kwargs = service.update.call_args[1]
        merged = call_kwargs["data"]["categories"]
        # "not_a_bool" is not isinstance(value, bool), so teams stays original
        assert merged["teams"] is True
        assert merged["fax"] is False

    async def test_update_creates_preference_if_none_exists(self) -> None:
        """When no preference exists, get_or_create_for_user creates one first."""
        service = _make_service()
        user_id = uuid4()
        # First call: no existing preference; second call after create: returns it
        created = _make_preference(user_id=user_id)
        service.get_one_or_none = AsyncMock(side_effect=[None, None])
        service.create = AsyncMock(return_value=created)
        service.update = AsyncMock(return_value=created)

        await service.update_for_user(
            user_id=user_id,
            data={"email_enabled": False},
        )

        # Should have created the preference
        service.create.assert_awaited_once()
        # Then updated it
        service.update.assert_awaited_once()

    async def test_update_without_categories_key(self) -> None:
        """When data has no 'categories' key, skip merge logic."""
        service = _make_service()
        user_id = uuid4()
        pref = _make_preference(user_id=user_id)
        service.get_one_or_none = AsyncMock(return_value=pref)
        service.update = AsyncMock(return_value=pref)

        await service.update_for_user(
            user_id=user_id,
            data={"email_enabled": True},
        )

        call_kwargs = service.update.call_args[1]
        # categories key should not be in data since we didn't send it
        assert "categories" not in call_kwargs["data"]


# ---------------------------------------------------------------------------
# is_category_enabled
# ---------------------------------------------------------------------------


class TestIsCategoryEnabled:
    """Tests for NotificationPreferenceService.is_category_enabled."""

    async def test_returns_true_when_no_preference_exists(self) -> None:
        """When no preferences saved, defaults apply (all enabled)."""
        service = _make_service()
        service.get_one_or_none = AsyncMock(return_value=None)

        result = await service.is_category_enabled(
            user_id=uuid4(),
            category="teams",
        )

        assert result is True

    async def test_returns_false_when_email_disabled(self) -> None:
        """When email_enabled is False, all categories are disabled."""
        service = _make_service()
        pref = _make_preference(email_enabled=False)
        service.get_one_or_none = AsyncMock(return_value=pref)

        result = await service.is_category_enabled(
            user_id=pref.user_id,
            category="teams",
        )

        assert result is False

    async def test_returns_true_when_email_and_category_enabled(self) -> None:
        """When email is on and category is on, returns True."""
        service = _make_service()
        categories = dict(DEFAULT_CATEGORIES)
        categories["teams"] = True
        pref = _make_preference(email_enabled=True, categories=categories)
        service.get_one_or_none = AsyncMock(return_value=pref)

        result = await service.is_category_enabled(
            user_id=pref.user_id,
            category="teams",
        )

        assert result is True

    async def test_returns_false_when_category_disabled(self) -> None:
        """When email is on but specific category is off, returns False."""
        service = _make_service()
        categories = dict(DEFAULT_CATEGORIES)
        categories["fax"] = False
        pref = _make_preference(email_enabled=True, categories=categories)
        service.get_one_or_none = AsyncMock(return_value=pref)

        result = await service.is_category_enabled(
            user_id=pref.user_id,
            category="fax",
        )

        assert result is False

    async def test_unknown_category_defaults_true(self) -> None:
        """When category key is not in the dict, .get defaults to True."""
        service = _make_service()
        pref = _make_preference(email_enabled=True, categories={"teams": True})
        service.get_one_or_none = AsyncMock(return_value=pref)

        result = await service.is_category_enabled(
            user_id=pref.user_id,
            category="new_future_category",
        )

        assert result is True

    async def test_email_disabled_overrides_category(self) -> None:
        """Even if category is explicitly True, email_enabled=False wins."""
        service = _make_service()
        categories = dict(DEFAULT_CATEGORIES)
        categories["system"] = True
        pref = _make_preference(email_enabled=False, categories=categories)
        service.get_one_or_none = AsyncMock(return_value=pref)

        result = await service.is_category_enabled(
            user_id=pref.user_id,
            category="system",
        )

        assert result is False
