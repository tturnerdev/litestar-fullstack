"""Audit logging utilities for capturing before/after change tracking.

Provides standalone helpers that controllers use to record structured audit entries
with field-level diffs into the existing AuditLog.details JSONB column, as well as
an :class:`AuditMixin` that services can inherit for declarative audit support.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import TYPE_CHECKING, Any, ClassVar
from uuid import UUID

from sqlalchemy import inspect as sa_inspect

if TYPE_CHECKING:
    from litestar import Request

    from app.db.models._audit_log import AuditLog
    from app.db.models._user import User
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


class AuditMixin:
    """Mixin for services that need declarative audit logging.

    Add this as a base class alongside ``SQLAlchemyAsyncRepositoryService``
    and set the class-level configuration attributes.  The mixin provides
    instance methods that use the host service's database session to write
    audit entries without requiring a separately injected ``AuditLogService``.

    Example::

        class DeviceService(AuditMixin, SQLAlchemyAsyncRepositoryService[Device]):
            audit_target_type = "device"
            audit_label_field = "name"
    """

    # --- class-level configuration (override in subclasses) ---

    audit_target_type: ClassVar[str]
    """Dot-free entity type string written to ``AuditLog.target_type`` (e.g. ``"device"``)."""

    audit_label_field: ClassVar[str] = "name"
    """Attribute name on the target entity used for ``AuditLog.target_label``."""

    audit_exclude_fields: ClassVar[set[str]] = {
        "id",
        "created_at",
        "updated_at",
        "sa_orm_sentinel",
    }
    """Field names excluded from snapshots.  Merged with ``_EXCLUDED_FIELDS`` at snapshot time."""

    # --- instance methods ---

    def capture_audit_snapshot(self, obj: Any) -> dict[str, Any]:
        """Serialize an ORM entity to a dict for audit comparison.

        Iterates over the model's table columns, converts non-JSON-native
        types (UUID, datetime, date) to strings, and skips relationships
        and excluded fields.

        Args:
            obj: A SQLAlchemy model instance.

        Returns:
            A dict of ``{column_name: serialized_value}`` suitable for JSON storage.
        """
        return capture_snapshot(obj, exclude=frozenset(self.audit_exclude_fields))

    @staticmethod
    def compute_audit_diff(
        before: dict[str, Any],
        after: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
        """Compute field-level differences between two snapshots.

        Only fields whose values differ are included in the returned dicts.

        Args:
            before: Snapshot captured *before* the mutation.
            after: Snapshot captured *after* the mutation.

        Returns:
            A 3-tuple of ``(before_changes, after_changes, changed_fields)``
            where each dict contains only the keys that changed, and
            ``changed_fields`` is the sorted list of those keys.
        """
        changed_before: dict[str, Any] = {}
        changed_after: dict[str, Any] = {}
        all_keys = set(before) | set(after)
        for key in sorted(all_keys):
            old_val = before.get(key)
            new_val = after.get(key)
            if old_val != new_val:
                changed_before[key] = old_val
                changed_after[key] = new_val
        changed_fields = sorted(changed_before.keys() | changed_after.keys())
        return changed_before, changed_after, changed_fields

    async def log_audit(
        self,
        action: str,
        actor: User,
        target: Any,
        *,
        before: dict[str, Any] | None = None,
        after: dict[str, Any] | None = None,
        request: Request[Any, Any, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditLog:
        """Write a structured audit log entry to the database.

        Creates an :class:`AuditLogService` that shares the current service's
        database session, builds a ``details`` payload containing before/after
        diffs and optional metadata, and delegates to
        :meth:`AuditLogService.log_action`.

        Args:
            action: Dot-delimited action name (e.g. ``"device.update"``).
            actor: The ``User`` performing the action.
            target: The ORM entity being acted upon (used for target_id and label).
            before: Snapshot dict captured *before* the operation (``None`` for creates).
            after: Snapshot dict captured *after* the operation (``None`` for deletes).
            request: Litestar request for extracting IP address and user-agent.
            metadata: Additional key-value pairs to store in ``details.metadata``.

        Returns:
            The created ``AuditLog`` instance.
        """
        from app.domain.admin.services import AuditLogService

        # Build the details payload
        details: dict[str, Any] = {}

        if before is not None and after is not None:
            before_diff, after_diff, changed_fields = self.compute_audit_diff(before, after)
            if changed_fields:
                details["before"] = before_diff
                details["after"] = after_diff
                details["changed_fields"] = changed_fields
        elif before is None and after is not None:
            # Create — record initial state
            details["before"] = None
            details["after"] = after
            details["changed_fields"] = sorted(after.keys())
        elif before is not None and after is None:
            # Delete — record final state
            details["before"] = before
            details["after"] = None
            details["changed_fields"] = sorted(before.keys())

        if metadata:
            details["metadata"] = metadata

        # Resolve target label from the configured label field
        target_label: str | None = None
        if hasattr(target, self.audit_label_field):
            label_value = getattr(target, self.audit_label_field, None)
            if label_value is not None:
                target_label = str(label_value)

        # Resolve target ID
        target_id: str | None = None
        if hasattr(target, "id"):
            raw_id = getattr(target, "id", None)
            if raw_id is not None:
                target_id = str(raw_id)

        # Create an AuditLogService sharing the same session
        # The host service exposes its session via self.repository.session
        session = self.repository.session  # type: ignore[attr-defined]
        audit_service = AuditLogService(session=session)

        return await audit_service.log_action(
            action=action,
            actor_id=actor.id,
            actor_email=actor.email,
            actor_name=actor.name,
            target_type=self.audit_target_type,
            target_id=target_id,
            target_label=target_label,
            details=details or None,
            request=request,
        )


__all__ = (
    "AuditMixin",
    "capture_snapshot",
    "compute_diff",
    "log_audit",
)
