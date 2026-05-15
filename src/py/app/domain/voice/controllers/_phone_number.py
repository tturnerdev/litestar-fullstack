"""Phone Number Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT
from sqlalchemy.orm import joinedload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.teams.guards import requires_feature_permission
from app.domain.voice.guards import requires_phone_number_access
from app.domain.voice.schemas import PhoneNumber, PhoneNumberCreate, PhoneNumberUpdate
from app.domain.voice.services import PhoneNumberService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class PhoneNumberController(Controller):
    """Phone Numbers."""

    tags = ["Voice Phone Numbers"]
    path = "/api/voice/phone-numbers"
    dependencies = create_service_dependencies(
        PhoneNumberService,
        key="phone_numbers_service",
        load=[joinedload(m.PhoneNumber.e911_registration)],
        filters={
            "id_filter": UUID,
            "search": "number,label",
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    ) | {
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(
        operation_id="ListPhoneNumbers",
        summary="List phone numbers",
        description="Retrieve a paginated list of the current user's phone numbers with E911 registration status. Supports search by number or label.",
        guards=[requires_feature_permission("voice_phone_numbers", "view")],
    )
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
        return phone_numbers_service.to_schema_enriched(results, total, filters)

    @post(
        operation_id="CreatePhoneNumber",
        summary="Create a phone number",
        description="Register a new phone number for the current user. Logs an audit entry and emits a creation event.",
        guards=[requires_feature_permission("voice_phone_numbers", "edit")],
        status_code=HTTP_201_CREATED,
    )
    async def create_phone_number(
        self,
        request: Request[m.User, Token, Any],
        phone_numbers_service: PhoneNumberService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: PhoneNumberCreate,
    ) -> PhoneNumber:
        """Create a new phone number."""
        obj = data.to_dict()
        obj["user_id"] = current_user.id
        db_obj = await phone_numbers_service.create(obj)
        request.app.emit(event_id="phone_number_created", phone_number_id=db_obj.id)
        after = capture_snapshot(db_obj)
        result = phone_numbers_service.to_schema_enriched(db_obj)
        await log_audit(
            audit_service,
            action="voice.phone_number.created",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="phone_number",
            target_id=db_obj.id,
            target_label=db_obj.number,
            before=None,
            after=after,
            request=request,
        )
        return result

    @get(
        operation_id="ListUnregisteredE911PhoneNumbers",
        summary="List phone numbers without E911",
        description="List active phone numbers within a team that lack an E911 registration. The caller must be a superuser or a member of the specified team.",
        path="/unregistered-e911",
        guards=[requires_feature_permission("voice_phone_numbers", "view")],
    )
    async def list_unregistered_e911(
        self,
        phone_numbers_service: PhoneNumberService,
        current_user: m.User,
        team_id: Annotated[
            UUID, Parameter(title="Team ID", description="The team to check for unregistered numbers.", query="teamId")
        ],
    ) -> list[PhoneNumber]:
        """List active phone numbers without E911 registration."""
        if not current_user.is_superuser and not any(tm.team_id == team_id for tm in current_user.teams):
            from litestar.exceptions import PermissionDeniedException

            raise PermissionDeniedException(detail="You do not have access to this team")
        results = await phone_numbers_service.get_unregistered_e911_numbers(team_id)
        return phone_numbers_service.to_schema_enriched(results)

    @get(
        operation_id="GetPhoneNumber",
        summary="Get phone number details",
        description="Retrieve a single phone number by ID with E911 registration status. The caller must own the phone number.",
        path="/{phone_number_id:uuid}",
        guards=[requires_feature_permission("voice_phone_numbers", "view"), requires_phone_number_access],
    )
    async def get_phone_number(
        self,
        phone_numbers_service: PhoneNumberService,
        current_user: m.User,
        phone_number_id: Annotated[
            UUID, Parameter(title="Phone Number ID", description="The phone number to retrieve.")
        ],
    ) -> PhoneNumber:
        """Get phone number details."""
        db_obj = await phone_numbers_service.get_one(id=phone_number_id, user_id=current_user.id)
        return phone_numbers_service.to_schema_enriched(db_obj)

    @patch(
        operation_id="UpdatePhoneNumber",
        summary="Update a phone number",
        description="Update a phone number's label or caller ID settings. Logs an audit entry and emits an update event. The caller must own the phone number.",
        path="/{phone_number_id:uuid}",
        guards=[requires_feature_permission("voice_phone_numbers", "edit"), requires_phone_number_access],
    )
    async def update_phone_number(
        self,
        request: Request[m.User, Token, Any],
        phone_numbers_service: PhoneNumberService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: PhoneNumberUpdate,
        phone_number_id: Annotated[UUID, Parameter(title="Phone Number ID", description="The phone number to update.")],
    ) -> PhoneNumber:
        """Update label, caller ID."""
        db_obj = await phone_numbers_service.get_one(id=phone_number_id, user_id=current_user.id)
        before = capture_snapshot(db_obj)
        db_obj = await phone_numbers_service.update(item_id=db_obj.id, data=data.to_dict())
        request.app.emit(event_id="phone_number_updated", phone_number_id=db_obj.id)
        after = capture_snapshot(db_obj)
        result = phone_numbers_service.to_schema_enriched(db_obj)
        await log_audit(
            audit_service,
            action="voice.phone_number.updated",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="phone_number",
            target_id=db_obj.id,
            target_label=db_obj.number,
            before=before,
            after=after,
            request=request,
        )
        return result

    @delete(
        operation_id="DeletePhoneNumber",
        summary="Delete a phone number",
        description="Delete a phone number record. Logs an audit entry and emits a deletion event. The caller must own the phone number.",
        path="/{phone_number_id:uuid}",
        guards=[requires_feature_permission("voice_phone_numbers", "edit"), requires_phone_number_access],
        return_dto=None,
        status_code=HTTP_204_NO_CONTENT,
    )
    async def delete_phone_number(
        self,
        request: Request[m.User, Token, Any],
        phone_numbers_service: PhoneNumberService,
        audit_service: AuditLogService,
        current_user: m.User,
        phone_number_id: Annotated[UUID, Parameter(title="Phone Number ID", description="The phone number to delete.")],
    ) -> None:
        """Delete a phone number."""
        db_obj = await phone_numbers_service.get_one(id=phone_number_id, user_id=current_user.id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.number
        request.app.emit(event_id="phone_number_deleted", phone_number_id=phone_number_id)
        await phone_numbers_service.delete(phone_number_id)
        await log_audit(
            audit_service,
            action="voice.phone_number.deleted",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="phone_number",
            target_id=phone_number_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )
