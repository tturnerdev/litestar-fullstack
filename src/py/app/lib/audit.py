"""Audit logging utilities for capturing before/after change tracking.

Provides helpers that controllers use to record structured audit entries
with field-level diffs into the existing AuditLog.details JSONB column.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import inspect as sa_inspect

if TYPE_CHECKING:
    from litestar import Request

    from app.db.models._audit_log import AuditLog
    from app.domain.admin.services import AuditLogService

# Fields excluded from snapshots — internal ORM/security columns
_EXCLUDED_FIELDS: frozenset[str] = frozenset(
    {
        "id",
        "sa_orm_sentinel",
        "created_at",
        "updated_at",
        "hashed_password",
        "totp_secret",
        "backup_codes",
        "token_hash",
        "reset_locked_until",
        "failed_reset_attempts",
    }
)


def capture_snapshot(obj: Any, *, exclude: frozenset[str] | None = None) -> dict[str, Any]:
    """Serialize a SQLAlchemy model instance to a plain dict for auditing.

    Only persisted (non-deferred, loaded) columns are included.
    Relationship attributes and internal fields are excluded.

    Args:
        obj: A SQLAlchemy model instance.
        exclude: Additional field names to exclude beyond the defaults.

    Returns:
        A dict of ``{column_name: value}`` suitable for JSON serialization.
    """
    skip = _EXCLUDED_FIELDS | (exclude or frozenset())
    mapper = sa_inspect(type(obj))
    result: dict[str, Any] = {}
    for col in mapper.columns:
        key = col.key
        if key in skip:
            continue
        try:
            value = getattr(obj, key)
        except Exception:  # noqa: BLE001
            continue
        # Convert non-JSON-native types to serializable forms
        if isinstance(value, UUID):
            value = str(value)
        elif isinstance(value, datetime):
            value = value.isoformat()
        elif isinstance(value, date):
            value = value.isoformat()
        result[key] = value
    return result


def compute_diff(
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> dict[str, Any]:
    """Return only the fields that changed between two snapshots.

    Args:
        before: Snapshot before the operation (None for creates).
        after: Snapshot after the operation (None for deletes).

    Returns:
        A dict with ``before`` and ``after`` sub-dicts containing only changed fields.
    """
    if before is None and after is None:
        return {}
    if before is None:
        return {"before": None, "after": after}
    if after is None:
        return {"before": before, "after": None}

    changed_before: dict[str, Any] = {}
    changed_after: dict[str, Any] = {}
    all_keys = set(before) | set(after)
    for key in all_keys:
        old_val = before.get(key)
        new_val = after.get(key)
        if old_val != new_val:
            changed_before[key] = old_val
            changed_after[key] = new_val

    if not changed_before and not changed_after:
        return {}
    return {"before": changed_before, "after": changed_after}


async def log_audit(
    audit_service: AuditLogService,
    *,
    action: str,
    actor_id: UUID | None = None,
    actor_email: str | None = None,
    actor_name: str | None = None,
    target_type: str | None = None,
    target_id: UUID | str | None = None,
    target_label: str | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    request: Request[Any, Any, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    """Write a structured audit log entry with optional before/after diff.

    This is the primary entry point for audit logging from controllers.
    It computes a diff from ``before``/``after`` snapshots and merges it
    with any extra ``metadata`` into the ``details`` JSONB column.

    Args:
        audit_service: The AuditLogService instance (shares the controller's session).
        action: Dot-delimited action name (e.g. ``team.create``, ``device.update``).
        actor_id: UUID of the user performing the action.
        actor_email: Email of the actor (preserved for history).
        target_type: Entity type affected (e.g. ``team``, ``user``).
        target_id: String ID of the target entity.
        target_label: Human-readable label (e.g. team name, user email).
        before: Snapshot dict before the operation (None for creates).
        after: Snapshot dict after the operation (None for deletes).
        request: Litestar request for extracting IP/user-agent.
        metadata: Additional key-value pairs to include in details.

    Returns:
        The created AuditLog instance.
    """
    details: dict[str, Any] = {}

    diff = compute_diff(before, after)
    if diff:
        details.update(diff)

    if metadata:
        details["metadata"] = metadata

    return await audit_service.log_action(
        action=action,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_name=actor_name,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        target_label=target_label,
        details=details or None,
        request=request,
    )


__all__ = (
    "capture_snapshot",
    "compute_diff",
    "log_audit",
)
