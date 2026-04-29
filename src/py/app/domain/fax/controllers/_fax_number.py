"""Fax Number Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from litestar import Controller, delete, get, patch
from litestar.exceptions import PermissionDeniedException
from litestar.params import Dependency, Parameter
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.fax.guards import requires_fax_number_access
from app.domain.fax.schemas import FaxNumber, FaxNumberUpdate
from app.domain.fax.services import FaxNumberService
from app.lib import constants
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination


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
    )

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
        data: FaxNumberUpdate,
        fax_numbers_service: FaxNumberService,
        current_user: m.User,
        fax_number_id: Annotated[UUID, Parameter(title="Fax Number ID", description="The fax number to update.")],
    ) -> FaxNumber:
        """Update a fax number's label or active status.

        Args:
            data: Fax Number Update
            fax_numbers_service: Fax Number Service
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
        db_obj = await fax_numbers_service.update(item_id=fax_number_id, data=data.to_dict())
        return fax_numbers_service.to_schema(db_obj, schema_type=FaxNumber)

    @delete(
        operation_id="DeleteFaxNumber",
        path="/api/fax/numbers/{fax_number_id:uuid}",
        guards=[requires_fax_number_access],
    )
    async def delete_fax_number(
        self,
        fax_numbers_service: FaxNumberService,
        current_user: m.User,
        fax_number_id: Annotated[UUID, Parameter(title="Fax Number ID", description="The fax number to delete.")],
    ) -> None:
        """Delete a fax number and its associated email routes."""
        existing = await fax_numbers_service.get(fax_number_id)
        if not _can_access_fax_number(current_user, existing):
            raise PermissionDeniedException(detail="Insufficient permissions to delete this fax number.")
        await fax_numbers_service.delete(fax_number_id)
