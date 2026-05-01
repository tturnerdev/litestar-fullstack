"""E911 Registration Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from sqlalchemy.orm import joinedload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.e911.guards import requires_team_membership
from app.domain.teams.guards import requires_feature_permission
from app.domain.e911.schemas import (
    E911Registration,
    E911RegistrationCreate,
    E911RegistrationUpdate,
    UnregisteredPhoneNumber,
)
from app.domain.e911.services import E911RegistrationService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class E911RegistrationController(Controller):
    """E911 Address Registrations."""

    tags = ["E911"]
    dependencies = create_service_dependencies(
        E911RegistrationService,
        key="e911_service",
        load=[
            joinedload(m.E911Registration.phone_number),
            joinedload(m.E911Registration.location),
        ],
        filters={
            "id_filter": UUID,
            "search": "address_line_1",
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
        operation_id="ListE911Registrations",
        path="/api/e911",
        guards=[requires_feature_permission("e911", "view"), requires_team_membership],
    )
    async def list_registrations(
        self,
        e911_service: E911RegistrationService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
        team_id: Annotated[UUID | None, Parameter(title="Team ID", description="Filter by team.", required=False)] = None,
    ) -> OffsetPagination[E911Registration]:
        """List E911 registrations.

        Args:
            e911_service: E911 Registration Service
            current_user: Current User
            filters: Filters
            team_id: Optional team ID filter

        Returns:
            OffsetPagination[E911Registration]
        """
        extra_filters = []
        if team_id:
            extra_filters.append(m.E911Registration.team_id == team_id)
        results, total = await e911_service.list_and_count(*filters, *extra_filters)
        return e911_service.to_schema(results, total, filters, schema_type=E911Registration)

    @post(
        operation_id="CreateE911Registration",
        path="/api/e911",
        guards=[requires_feature_permission("e911", "edit"), requires_team_membership],
    )
    async def create_registration(
        self,
        request: Request[m.User, Token, Any],
        e911_service: E911RegistrationService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: E911RegistrationCreate,
    ) -> E911Registration:
        """Create a new E911 registration.

        Args:
            request: The current request
            e911_service: E911 Registration Service
            audit_service: Audit Log Service
            current_user: Current User
            data: E911 Registration Create

        Returns:
            E911Registration
        """
        obj = data.to_dict()
        db_obj = await e911_service.create(obj)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="e911.create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="e911_registration",
            target_id=db_obj.id,
            target_label=f"{db_obj.address_line_1}, {db_obj.city}",
            before=None,
            after=after,
            request=request,
        )
        return e911_service.to_schema(db_obj, schema_type=E911Registration)

    @get(
        operation_id="GetE911Registration",
        path="/api/e911/{registration_id:uuid}",
        guards=[requires_feature_permission("e911", "view"), requires_team_membership],
    )
    async def get_registration(
        self,
        e911_service: E911RegistrationService,
        registration_id: Annotated[UUID, Parameter(title="Registration ID", description="The E911 registration to retrieve.")],
    ) -> E911Registration:
        """Get details about an E911 registration.

        Args:
            e911_service: E911 Registration Service
            registration_id: Registration ID

        Returns:
            E911Registration
        """
        db_obj = await e911_service.get(registration_id)
        return e911_service.to_schema(db_obj, schema_type=E911Registration)

    @patch(
        operation_id="UpdateE911Registration",
        path="/api/e911/{registration_id:uuid}",
        guards=[requires_feature_permission("e911", "edit"), requires_team_membership],
    )
    async def update_registration(
        self,
        request: Request[m.User, Token, Any],
        data: E911RegistrationUpdate,
        e911_service: E911RegistrationService,
        audit_service: AuditLogService,
        current_user: m.User,
        registration_id: Annotated[UUID, Parameter(title="Registration ID", description="The E911 registration to update.")],
    ) -> E911Registration:
        """Update an E911 registration.

        Args:
            request: The current request
            data: E911 Registration Update
            e911_service: E911 Registration Service
            audit_service: Audit Log Service
            current_user: Current User
            registration_id: Registration ID

        Returns:
            E911Registration
        """
        before = capture_snapshot(await e911_service.get(registration_id))
        await e911_service.update(
            item_id=registration_id,
            data=data.to_dict(),
        )
        fresh_obj = await e911_service.get_one(id=registration_id)
        after = capture_snapshot(fresh_obj)
        await log_audit(
            audit_service,
            action="e911.update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="e911_registration",
            target_id=registration_id,
            target_label=f"{fresh_obj.address_line_1}, {fresh_obj.city}",
            before=before,
            after=after,
            request=request,
        )
        return e911_service.to_schema(fresh_obj, schema_type=E911Registration)

    @delete(
        operation_id="DeleteE911Registration",
        path="/api/e911/{registration_id:uuid}",
        guards=[requires_feature_permission("e911", "edit"), requires_team_membership],
    )
    async def delete_registration(
        self,
        request: Request[m.User, Token, Any],
        e911_service: E911RegistrationService,
        audit_service: AuditLogService,
        current_user: m.User,
        registration_id: Annotated[UUID, Parameter(title="Registration ID", description="The E911 registration to delete.")],
    ) -> None:
        """Delete an E911 registration.

        Args:
            request: The current request
            e911_service: E911 Registration Service
            audit_service: Audit Log Service
            current_user: Current User
            registration_id: Registration ID
        """
        db_obj = await e911_service.get(registration_id)
        before = capture_snapshot(db_obj)
        target_label = f"{db_obj.address_line_1}, {db_obj.city}"
        await e911_service.delete(registration_id)
        await log_audit(
            audit_service,
            action="e911.delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="e911_registration",
            target_id=registration_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )

    @post(
        operation_id="ValidateE911Registration",
        path="/api/e911/{registration_id:uuid}/validate",
        guards=[requires_feature_permission("e911", "edit"), requires_team_membership],
    )
    async def validate_registration(
        self,
        request: Request[m.User, Token, Any],
        e911_service: E911RegistrationService,
        audit_service: AuditLogService,
        current_user: m.User,
        registration_id: Annotated[UUID, Parameter(title="Registration ID", description="The E911 registration to validate.")],
    ) -> E911Registration:
        """Validate an E911 registration address.

        This is a stub that marks the registration as validated.
        In production this would call a carrier API for real address validation.

        Args:
            request: The current request
            e911_service: E911 Registration Service
            audit_service: Audit Log Service
            current_user: Current User
            registration_id: Registration ID

        Returns:
            E911Registration
        """
        before = capture_snapshot(await e911_service.get(registration_id))
        db_obj = await e911_service.validate_registration(registration_id)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="e911.validate",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="e911_registration",
            target_id=registration_id,
            target_label=f"{db_obj.address_line_1}, {db_obj.city}",
            before=before,
            after=after,
            request=request,
        )
        return e911_service.to_schema(db_obj, schema_type=E911Registration)

    @get(
        operation_id="ListUnregisteredPhoneNumbers",
        path="/api/e911/unregistered",
        guards=[requires_feature_permission("e911", "view"), requires_team_membership],
    )
    async def list_unregistered(
        self,
        e911_service: E911RegistrationService,
        current_user: m.User,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team to check for unregistered numbers.")],
    ) -> list[UnregisteredPhoneNumber]:
        """List phone numbers without E911 registrations.

        Args:
            e911_service: E911 Registration Service
            current_user: Current User
            team_id: Team ID

        Returns:
            list[UnregisteredPhoneNumber]
        """
        numbers = await e911_service.get_unregistered_numbers(team_id)
        return [
            UnregisteredPhoneNumber(
                id=n.id,
                number=n.number,
                label=n.label,
                number_type=n.number_type,
                user_id=n.user_id,
                team_id=n.team_id,
            )
            for n in numbers
        ]
