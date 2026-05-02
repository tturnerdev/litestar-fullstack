"""Phone Numbers CRUD Controller."""

from __future__ import annotations

from datetime import date, datetime
from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

import msgspec
from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Dependency
from sqlalchemy import inspect as sa_inspect

from app.db import models as m
from app.domain.accounts.guards import requires_active_user
from app.domain.admin.deps import provide_audit_log_service
from app.domain.phone_numbers.schemas import (
    PhoneNumberCreate,
    PhoneNumberDetail,
    PhoneNumberList,
    PhoneNumberUpdate,
)
from app.domain.phone_numbers.services import PhoneNumberService
from app.lib.deps import create_service_dependencies
from app.lib.schema import Message

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService

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


class PhoneNumberController(Controller):
    """Phone number CRUD endpoints."""

    tags = ["Phone Numbers"]
    path = "/api/phone-numbers"
    guards = [requires_active_user]
    dependencies = create_service_dependencies(
        PhoneNumberService,
        key="phone_number_service",
        error_messages={
            "duplicate_key": "This phone number already exists.",
            "integrity": "Phone number operation failed.",
        },
        filters={
            "id_filter": UUID,
            "search": "number,friendly_name",
            "pagination_type": "limit_offset",
            "pagination_size": 25,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    ) | {
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(operation_id="ManageListPhoneNumbers", path="/")
    async def list_phone_numbers(
        self,
        phone_number_service: PhoneNumberService,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[PhoneNumberList]:
        """List phone numbers with pagination.

        Args:
            phone_number_service: Phone number service.
            filters: Filter and pagination parameters.

        Returns:
            Paginated phone number list.
        """
        results, total = await phone_number_service.list_and_count(*filters)
        return phone_number_service.to_schema(results, total, filters, schema_type=PhoneNumberList)

    @get(operation_id="ManageGetPhoneNumber", path="/{phone_number_id:uuid}")
    async def get_phone_number(
        self,
        phone_number_service: PhoneNumberService,
        phone_number_id: UUID,
    ) -> PhoneNumberDetail:
        """Get a phone number by ID.

        Args:
            phone_number_service: Phone number service.
            phone_number_id: ID of the phone number.

        Returns:
            Phone number details.
        """
        result = await phone_number_service.get(phone_number_id)
        return phone_number_service.to_schema(result, schema_type=PhoneNumberDetail)

    @post(operation_id="ManageCreatePhoneNumber", path="/")
    async def create_phone_number(
        self,
        request: Request[m.User, Token, Any],
        phone_number_service: PhoneNumberService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: PhoneNumberCreate,
    ) -> PhoneNumberDetail:
        """Create a new phone number.

        Args:
            request: The current request.
            phone_number_service: Phone number service.
            audit_service: Audit Log Service.
            current_user: Current User.
            data: Create payload.

        Returns:
            Created phone number details.
        """
        result = await phone_number_service.create(data.to_dict(), auto_commit=True)
        after = _capture_snapshot(result)
        await _log_audit(
            audit_service,
            action="phone_number.created",
            actor=current_user,
            target_type="phone_number",
            target_id=result.id,
            target_label=result.number,
            after=after,
            request=request,
        )
        return phone_number_service.to_schema(result, schema_type=PhoneNumberDetail)

    @patch(operation_id="ManageUpdatePhoneNumber", path="/{phone_number_id:uuid}")
    async def update_phone_number(
        self,
        request: Request[m.User, Token, Any],
        phone_number_service: PhoneNumberService,
        audit_service: AuditLogService,
        current_user: m.User,
        phone_number_id: UUID,
        data: PhoneNumberUpdate,
    ) -> PhoneNumberDetail:
        """Update a phone number.

        Args:
            request: The current request.
            phone_number_service: Phone number service.
            audit_service: Audit Log Service.
            current_user: Current User.
            phone_number_id: ID of the phone number.
            data: Update payload.

        Returns:
            Updated phone number details.
        """
        before = _capture_snapshot(await phone_number_service.get(phone_number_id))
        update_data: dict[str, Any] = {}
        for field in data.__struct_fields__:
            value = getattr(data, field)
            if value is not msgspec.UNSET:
                update_data[field] = value

        await phone_number_service.update(item_id=phone_number_id, data=update_data, auto_commit=True)
        fresh_obj = await phone_number_service.get_one(id=phone_number_id)
        after = _capture_snapshot(fresh_obj)
        await _log_audit(
            audit_service,
            action="phone_number.updated",
            actor=current_user,
            target_type="phone_number",
            target_id=phone_number_id,
            target_label=fresh_obj.number,
            before=before,
            after=after,
            request=request,
        )
        return phone_number_service.to_schema(fresh_obj, schema_type=PhoneNumberDetail)

    @delete(operation_id="ManageDeletePhoneNumber", path="/{phone_number_id:uuid}", status_code=200)
    async def delete_phone_number(
        self,
        request: Request[m.User, Token, Any],
        phone_number_service: PhoneNumberService,
        audit_service: AuditLogService,
        current_user: m.User,
        phone_number_id: UUID,
    ) -> Message:
        """Delete a phone number.

        Args:
            request: The current request.
            phone_number_service: Phone number service.
            audit_service: Audit Log Service.
            current_user: Current User.
            phone_number_id: ID of the phone number.

        Returns:
            Success message.
        """
        phone = await phone_number_service.get(phone_number_id)
        before = _capture_snapshot(phone)
        target_label = phone.number
        await phone_number_service.delete(phone_number_id)
        await _log_audit(
            audit_service,
            action="phone_number.deleted",
            actor=current_user,
            target_type="phone_number",
            target_id=phone_number_id,
            target_label=target_label,
            before=before,
            request=request,
        )
        return Message(message=f"Phone number {target_label} deleted successfully")
