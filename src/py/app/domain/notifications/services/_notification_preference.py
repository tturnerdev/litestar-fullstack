"""Notification preference service."""

from __future__ import annotations

from typing import TYPE_CHECKING

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m
from app.db.models._notification_preference import DEFAULT_CATEGORIES

if TYPE_CHECKING:
    from uuid import UUID


VALID_CATEGORIES = frozenset(DEFAULT_CATEGORIES.keys())


class NotificationPreferenceService(service.SQLAlchemyAsyncRepositoryService[m.NotificationPreference]):
    """Handles database operations for notification preferences."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.NotificationPreference]):
        """Notification Preference Repository."""

        model_type = m.NotificationPreference

    repository_type = Repo
    match_fields = ["user_id"]

    async def get_or_create_for_user(self, user_id: UUID) -> m.NotificationPreference:
        """Get existing preferences or create defaults for a user.

        Args:
            user_id: The user's UUID.

        Returns:
            The notification preference record.
        """
        existing = await self.get_one_or_none(user_id=user_id)
        if existing is not None:
            return existing
        return await self.create(
            data={
                "user_id": user_id,
                "email_enabled": True,
                "categories": dict(DEFAULT_CATEGORIES),
            },
        )

    async def update_for_user(
        self,
        user_id: UUID,
        data: dict[str, object],
    ) -> m.NotificationPreference:
        """Update preferences for a user, creating defaults first if needed.

        Args:
            user_id: The user's UUID.
            data: Fields to update.

        Returns:
            The updated notification preference record.
        """
        pref = await self.get_or_create_for_user(user_id)

        # If categories are being updated, validate and merge with existing
        if "categories" in data and isinstance(data["categories"], dict):
            merged = dict(pref.categories)
            for key, value in data["categories"].items():
                if key in VALID_CATEGORIES and isinstance(value, bool):
                    merged[key] = value
            data["categories"] = merged

        return await self.update(item_id=pref.id, data=data)

    async def is_category_enabled(self, user_id: UUID, category: str) -> bool:
        """Check if a notification category is enabled for a user.

        Args:
            user_id: The user's UUID.
            category: The notification category to check.

        Returns:
            True if both email is enabled and the category is enabled.
        """
        pref = await self.get_one_or_none(user_id=user_id)
        if pref is None:
            # No preferences saved means defaults apply (all enabled)
            return True
        if not pref.email_enabled:
            return False
        return pref.categories.get(category, True)
