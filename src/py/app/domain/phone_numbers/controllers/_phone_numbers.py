"""Phone Numbers CRUD Controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

import msgspec
from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Dependency
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.teams.guards import requires_feature_permission
from app.domain.phone_numbers.schemas import (
    PhoneNumberCreate,
    PhoneNumberDetail,
    PhoneNumberList,
    PhoneNumberUpdate,
)
from app.domain.phone_numbers.services import PhoneNumberService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class PhoneNumberController(Controller):
    """Phone number CRUD endpoints."""

    tags = ["Phone Numbers"]
    path = "/api/phone-numbers"
    guards = [requires_feature_permission("voice", "view")]
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

    @get(operation_id="ManageListPhoneNumbers", summary="List phone numbers", path="/")
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

    @get(operation_id="ManageGetPhoneNumber", summary="Get a phone number", path="/{phone_number_id:uuid}")
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

    @post(operation_id="ManageCreatePhoneNumber", summary="Create a phone number", path="/", status_code=HTTP_201_CREATED, guards=[requires_feature_permission("voice", "edit")])
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
        request.app.emit(event_id="phone_number_created", phone_number_id=result.id)
        after = capture_snapshot(result)
        await log_audit(
            audit_service,
            action="phone_number.created",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="phone_number",
            target_id=result.id,
            target_label=result.number,
            after=after,
            request=request,
        )
        return phone_number_service.to_schema(result, schema_type=PhoneNumberDetail)

    @patch(operation_id="ManageUpdatePhoneNumber", summary="Update a phone number", path="/{phone_number_id:uuid}", guards=[requires_feature_permission("voice", "edit")])
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
        before = capture_snapshot(await phone_number_service.get(phone_number_id))
        update_data: dict[str, Any] = {}
        for field in data.__struct_fields__:
            value = getattr(data, field)
            if value is not msgspec.UNSET:
                update_data[field] = value

        fresh_obj = await phone_number_service.update(item_id=phone_number_id, data=update_data, auto_commit=True)
        request.app.emit(event_id="phone_number_updated", phone_number_id=fresh_obj.id)
        after = capture_snapshot(fresh_obj)
        await log_audit(
            audit_service,
            action="phone_number.updated",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="phone_number",
            target_id=phone_number_id,
            target_label=fresh_obj.number,
            before=before,
            after=after,
            request=request,
        )
        return phone_number_service.to_schema(fresh_obj, schema_type=PhoneNumberDetail)

    @delete(operation_id="ManageDeletePhoneNumber", summary="Delete a phone number", path="/{phone_number_id:uuid}", status_code=HTTP_204_NO_CONTENT, return_dto=None, guards=[requires_feature_permission("voice", "edit")])
    async def delete_phone_number(
        self,
        request: Request[m.User, Token, Any],
        phone_number_service: PhoneNumberService,
        audit_service: AuditLogService,
        current_user: m.User,
        phone_number_id: UUID,
    ) -> None:
        """Delete a phone number."""
        phone = await phone_number_service.get(phone_number_id)
        before = capture_snapshot(phone)
        target_label = phone.number
        request.app.emit(event_id="phone_number_deleted", phone_number_id=phone_number_id)
        await phone_number_service.delete(phone_number_id, auto_commit=True)
        await log_audit(
            audit_service,
            action="phone_number.deleted",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="phone_number",
            target_id=phone_number_id,
            target_label=target_label,
            before=before,
            request=request,
        )
