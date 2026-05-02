"""Notification Preference Controllers."""

from __future__ import annotations

from datetime import date, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

import structlog
from litestar import Controller, Request, get, patch
from litestar.di import Provide
from sqlalchemy import inspect as sa_inspect

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.notifications.deps import provide_notification_preference_service
from app.domain.notifications.schemas import NotificationPreference, NotificationPreferenceUpdate

if TYPE_CHECKING:
    from app.domain.admin.services import AuditLogService
    from app.domain.notifications.services import NotificationPreferenceService

logger = structlog.get_logger()

_SNAPSHOT_EXCLUDE: frozenset[str] = frozenset(
    {"id", "sa_orm_sentinel", "created_at", "updated_at", "hashed_password", "totp_secret", "backup_codes"}
)


def _capture_snapshot(obj: Any) -> dict[str, Any]:
    """Serialize a SQLAlchemy model instance to a plain dict for audit details."""
    mapper = sa_inspect(type(obj))
    result: dict[str, Any] = {}
    for col in mapper.columns:
        key = col.key
        if key in _SNAPSHOT_EXCLUDE:
            continue
        try:
            value = getattr(obj, key)
        except Exception:  # noqa: BLE001, S112
            continue
        if isinstance(value, UUID):
            value = str(value)
        elif isinstance(value, (datetime, date)):
            value = value.isoformat()
        result[key] = value
    return result


async def _log_audit(
    audit_service: AuditLogService,
    *,
    action: str,
    actor: m.User,
    target_type: str,
    target_id: UUID,
    target_label: str,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    request: Request[Any, Any, Any] | None = None,
) -> None:
    """Write an audit log entry with optional before/after diff."""
    details: dict[str, Any] = {}
    if before is not None or after is not None:
        if before is None:
            details = {"before": None, "after": after}
        elif after is None:
            details = {"before": before, "after": None}
        else:
            changed_before: dict[str, Any] = {}
            changed_after: dict[str, Any] = {}
            for key in set(before) | set(after):
                if before.get(key) != after.get(key):
                    changed_before[key] = before.get(key)
                    changed_after[key] = after.get(key)
            if changed_before or changed_after:
                details = {"before": changed_before, "after": changed_after}

    await audit_service.log_action(
        action=action,
        actor_id=actor.id,
        actor_email=actor.email,
        actor_name=actor.name,
        target_type=target_type,
        target_id=str(target_id),
        target_label=target_label,
        details=details or None,
        request=request,
    )


class NotificationPreferenceController(Controller):
    """Handles notification preference operations for the current user."""

    tags = ["Notifications"]
    path = "/api/notifications/preferences"
    dependencies = {
        "notification_preference_service": Provide(provide_notification_preference_service),
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(
        operation_id="GetNotificationPreferences",
        summary="Get notification preferences",
        description="Get the current user's notification preferences.",
    )
    async def get_preferences(
        self,
        notification_preference_service: NotificationPreferenceService,
        current_user: m.User,
    ) -> NotificationPreference:
        """Get the current user's notification preferences.

        Returns:
            The notification preference record.
        """
        db_obj = await notification_preference_service.get_or_create_for_user(current_user.id)
        return notification_preference_service.to_schema(db_obj, schema_type=NotificationPreference)

    @patch(
        operation_id="UpdateNotificationPreferences",
        summary="Update notification preferences",
        description="Update the current user's notification preferences.",
    )
    async def update_preferences(
        self,
        request: Request[m.User, Any, Any],
        notification_preference_service: NotificationPreferenceService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: NotificationPreferenceUpdate,
    ) -> NotificationPreference:
        """Update the current user's notification preferences.

        Args:
            request: The current request.
            notification_preference_service: The notification preference service.
            audit_service: Audit Log Service.
            current_user: The current user.
            data: The update data.

        Returns:
            The updated notification preference record.
        """
        existing = await notification_preference_service.get_or_create_for_user(current_user.id)
        before = _capture_snapshot(existing)
        db_obj = await notification_preference_service.update_for_user(
            user_id=current_user.id,
            data=data.to_dict(),
        )
        after = _capture_snapshot(db_obj)
        await _log_audit(
            audit_service,
            action="notification_preference.updated",
            actor=current_user,
            target_type="notification_preference",
            target_id=db_obj.id,
            target_label=current_user.email,
            before=before,
            after=after,
            request=request,
        )
        return notification_preference_service.to_schema(db_obj, schema_type=NotificationPreference)
