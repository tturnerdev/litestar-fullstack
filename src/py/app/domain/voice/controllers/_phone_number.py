"""Phone Number Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from litestar import Controller, get, patch, post
from litestar.params import Dependency, Parameter

from app.db import models as m
from app.domain.voice.guards import requires_phone_number_access
from app.domain.voice.schemas import PhoneNumber, PhoneNumberCreate, PhoneNumberUpdate
from app.domain.voice.services import PhoneNumberService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination


class PhoneNumberController(Controller):
    """Phone Numbers."""

    tags = ["Voice - Phone Numbers"]
    path = "/api/voice/phone-numbers"
    dependencies = create_service_dependencies(
        PhoneNumberService,
        key="phone_numbers_service",
        filters={
            "id_filter": UUID,
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    )

    @get(operation_id="ListPhoneNumbers")
    async def list_phone_numbers(
        self,
        phone_numbers_service: PhoneNumberService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[PhoneNumber]:
        """List user's phone numbers."""
        results, total = await phone_numbers_service.list_and_count(
            *filters,
            m.PhoneNumber.user_id == current_user.id,
        )
        return phone_numbers_service.to_schema(results, total, filters, schema_type=PhoneNumber)

    @post(operation_id="CreatePhoneNumber")
    async def create_phone_number(
        self,
        phone_numbers_service: PhoneNumberService,
        current_user: m.User,
        data: PhoneNumberCreate,
    ) -> PhoneNumber:
        """Create a new phone number."""
        obj = data.to_dict()
        obj["user_id"] = current_user.id
        db_obj = await phone_numbers_service.create(obj)
        return phone_numbers_service.to_schema(db_obj, schema_type=PhoneNumber)

    @get(operation_id="GetPhoneNumber", path="/{phone_number_id:uuid}", guards=[requires_phone_number_access])
    async def get_phone_number(
        self,
        phone_numbers_service: PhoneNumberService,
        current_user: m.User,
        phone_number_id: Annotated[UUID, Parameter(title="Phone Number ID", description="The phone number to retrieve.")],
    ) -> PhoneNumber:
        """Get phone number details."""
        db_obj = await phone_numbers_service.get_one(id=phone_number_id, user_id=current_user.id)
        return phone_numbers_service.to_schema(db_obj, schema_type=PhoneNumber)

    @patch(operation_id="UpdatePhoneNumber", path="/{phone_number_id:uuid}", guards=[requires_phone_number_access])
    async def update_phone_number(
        self,
        phone_numbers_service: PhoneNumberService,
        current_user: m.User,
        data: PhoneNumberUpdate,
        phone_number_id: Annotated[UUID, Parameter(title="Phone Number ID", description="The phone number to update.")],
    ) -> PhoneNumber:
        """Update label, caller ID."""
        db_obj = await phone_numbers_service.get_one(id=phone_number_id, user_id=current_user.id)
        db_obj = await phone_numbers_service.update(item_id=db_obj.id, data=data.to_dict())
        return phone_numbers_service.to_schema(db_obj, schema_type=PhoneNumber)
