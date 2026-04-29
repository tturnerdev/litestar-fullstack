"""Fax Number Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch
from litestar.di import Provide
from litestar.exceptions import PermissionDeniedException
from litestar.params import Dependency, Parameter
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.fax.guards import requires_fax_number_access
from app.domain.fax.schemas import FaxNumber, FaxNumberUpdate
from app.domain.fax.services import FaxNumberService
from app.domain.notifications.deps import provide_notifications_service
from app.lib import constants
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService
    from app.domain.notifications.services import NotificationService


def _can_access_fax_number(user: m.User, fax_number: m.FaxNumber) -> bool:
    """Check if a user can access a specific fax number."""
    if user.is_superuser:
        return True
    if any(r.role_name == constants.SUPERUSER_ACCESS_ROLE for r in user.roles):
        return True
    if fax_number.user_id == user.id:
        return True
    if fax_number.team_id is not None:
        return any(membership.team_id == fax_number.team_id for membership in user.teams)
    return False


class FaxNumberController(Controller):
    """Fax Numbers."""

    tags = ["Fax Numbers"]
    dependencies = create_service_dependencies(
        FaxNumberService,
        key="fax_numbers_service",
        load=[selectinload(m.FaxNumber.email_routes)],
        filters={
            "id_filter": UUID,
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    ) | {
        "audit_service": Provide(provide_audit_log_service),
        "notifications_service": Provide(provide_notifications_service),
    }

    @get(component="fax/number-list", operation_id="ListFaxNumbers", path="/api/fax/numbers")
    async def list_fax_numbers(
        self,
        fax_numbers_service: FaxNumberService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[FaxNumber]:
        """List fax numbers the current user can access.

        Args:
            fax_numbers_service: Fax Number Service
            current_user: Current User
            filters: Filters

        Returns:
            OffsetPagination[FaxNumber]
        """
        user_team_ids = select(m.TeamMember.team_id).where(m.TeamMember.user_id == current_user.id).scalar_subquery()
        results, total = await fax_numbers_service.list_and_count(
            *filters,
            (m.FaxNumber.user_id == current_user.id) | (m.FaxNumber.team_id.in_(user_team_ids)),
        )
        return fax_numbers_service.to_schema(results, total, filters, schema_type=FaxNumber)

    @get(
        operation_id="GetFaxNumber",
        path="/api/fax/numbers/{fax_number_id:uuid}",
        guards=[requires_fax_number_access],
    )
    async def get_fax_number(
        self,
        fax_numbers_service: FaxNumberService,
        current_user: m.User,
        fax_number_id: Annotated[UUID, Parameter(title="Fax Number ID", description="The fax number to retrieve.")],
    ) -> FaxNumber:
        """Get details about a fax number.

        Args:
            fax_numbers_service: Fax Number Service
            current_user: Current User
            fax_number_id: Fax Number ID

        Raises:
            PermissionDeniedException: If user cannot access this fax number

        Returns:
            FaxNumber
        """
        db_obj = await fax_numbers_service.get(fax_number_id)
        if not _can_access_fax_number(current_user, db_obj):
            raise PermissionDeniedException(detail="Insufficient permissions to access this fax number.")
        return fax_numbers_service.to_schema(db_obj, schema_type=FaxNumber)

    @patch(
        operation_id="UpdateFaxNumber",
        path="/api/fax/numbers/{fax_number_id:uuid}",
        guards=[requires_fax_number_access],
    )
    async def update_fax_number(
        self,
        request: Request[m.User, Token, Any],
        data: FaxNumberUpdate,
        fax_numbers_service: FaxNumberService,
        audit_service: AuditLogService,
        current_user: m.User,
        fax_number_id: Annotated[UUID, Parameter(title="Fax Number ID", description="The fax number to update.")],
    ) -> FaxNumber:
        """Update a fax number's label or active status.

        Args:
            request: The current request
            data: Fax Number Update
            fax_numbers_service: Fax Number Service
            audit_service: Audit Log Service
            current_user: Current User
            fax_number_id: Fax Number ID

        Raises:
            PermissionDeniedException: If user cannot access this fax number

        Returns:
            FaxNumber
        """
        existing = await fax_numbers_service.get(fax_number_id)
        if not _can_access_fax_number(current_user, existing):
            raise PermissionDeniedException(detail="Insufficient permissions to access this fax number.")
        before = capture_snapshot(existing)
        db_obj = await fax_numbers_service.update(item_id=fax_number_id, data=data.to_dict())
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="fax.number_update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="fax_number",
            target_id=fax_number_id,
            target_label=db_obj.number,
            before=before,
            after=after,
            request=request,
        )
        return fax_numbers_service.to_schema(db_obj, schema_type=FaxNumber)

    @delete(
        operation_id="DeleteFaxNumber",
        path="/api/fax/numbers/{fax_number_id:uuid}",
        guards=[requires_fax_number_access],
    )
    async def delete_fax_number(
        self,
        request: Request[m.User, Token, Any],
        fax_numbers_service: FaxNumberService,
        audit_service: AuditLogService,
        notifications_service: NotificationService,
        current_user: m.User,
        fax_number_id: Annotated[UUID, Parameter(title="Fax Number ID", description="The fax number to delete.")],
    ) -> None:
        """Delete a fax number and its associated email routes."""
        existing = await fax_numbers_service.get(fax_number_id)
        if not _can_access_fax_number(current_user, existing):
            raise PermissionDeniedException(detail="Insufficient permissions to delete this fax number.")
        before = capture_snapshot(existing)
        target_label = existing.number
        owner_id = existing.user_id
        await fax_numbers_service.delete(fax_number_id)
        await log_audit(
            audit_service,
            action="fax.number_delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="fax_number",
            target_id=fax_number_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )
        try:
            await notifications_service.notify(
                user_id=owner_id,
                title="Fax Number Removed",
                message=f"Your fax number '{target_label}' has been removed.",
                category="fax",
                action_url="/fax/numbers",
            )
        except Exception:
            pass
