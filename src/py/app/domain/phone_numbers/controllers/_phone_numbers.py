"""Phone Numbers CRUD Controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

import msgspec
from litestar import Controller, delete, get, patch, post
from litestar.params import Dependency

from app.db import models as m
from app.domain.accounts.guards import requires_active_user
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
    )

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
        phone_number_service: PhoneNumberService,
        data: PhoneNumberCreate,
    ) -> PhoneNumberDetail:
        """Create a new phone number.

        Args:
            phone_number_service: Phone number service.
            data: Create payload.

        Returns:
            Created phone number details.
        """
        result = await phone_number_service.create(data.to_dict(), auto_commit=True)
        return phone_number_service.to_schema(result, schema_type=PhoneNumberDetail)

    @patch(operation_id="ManageUpdatePhoneNumber", path="/{phone_number_id:uuid}")
    async def update_phone_number(
        self,
        phone_number_service: PhoneNumberService,
        phone_number_id: UUID,
        data: PhoneNumberUpdate,
    ) -> PhoneNumberDetail:
        """Update a phone number.

        Args:
            phone_number_service: Phone number service.
            phone_number_id: ID of the phone number.
            data: Update payload.

        Returns:
            Updated phone number details.
        """
        update_data: dict[str, Any] = {}
        for field in data.__struct_fields__:
            value = getattr(data, field)
            if value is not msgspec.UNSET:
                update_data[field] = value

        result = await phone_number_service.update(item_id=phone_number_id, data=update_data, auto_commit=True)
        return phone_number_service.to_schema(result, schema_type=PhoneNumberDetail)

    @delete(operation_id="ManageDeletePhoneNumber", path="/{phone_number_id:uuid}", status_code=200)
    async def delete_phone_number(
        self,
        phone_number_service: PhoneNumberService,
        phone_number_id: UUID,
    ) -> Message:
        """Delete a phone number.

        Args:
            phone_number_service: Phone number service.
            phone_number_id: ID of the phone number.

        Returns:
            Success message.
        """
        phone = await phone_number_service.get(phone_number_id)
        await phone_number_service.delete(phone_number_id)
        return Message(message=f"Phone number {phone.number} deleted successfully")
