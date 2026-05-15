"""Fax Email Route Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any

from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.exceptions import ClientException, NotFoundException, PermissionDeniedException
from litestar.params import Dependency, Parameter
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.fax.controllers._fax_number import _can_access_fax_number
from app.domain.fax.deps import provide_fax_numbers_service
from app.domain.fax.guards import requires_fax_number_access
from app.domain.fax.schemas import FaxEmailRoute, FaxEmailRouteCreate, FaxEmailRouteUpdate
from app.domain.fax.services import FaxEmailRouteService
from app.domain.teams.guards import requires_feature_permission
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from uuid import UUID

    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService
    from app.domain.fax.services import FaxNumberService


class FaxEmailRouteController(Controller):
    """Fax Email Routes."""

    path = "/api/fax/numbers/{fax_number_id:uuid}/email-routes"
    tags = ["Fax Email Routes"]
    dependencies = create_service_dependencies(
        FaxEmailRouteService,
        key="fax_email_routes_service",
        load=[selectinload(m.FaxEmailRoute.fax_number)],
        error_messages={
            "duplicate_key": "This email route already exists.",
            "integrity": "Email route operation failed.",
        },
        filters={
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
            "search": "email_address",
        },
    ) | {
        "fax_numbers_service": Provide(provide_fax_numbers_service),
        "audit_service": Provide(provide_audit_log_service),
    }

    async def _verify_fax_number_access(
        self,
        fax_numbers_service: FaxNumberService,
        current_user: m.User,
        fax_number_id: UUID,
    ) -> m.FaxNumber:
        """Verify the user can access the fax number and return it.

        Raises:
            NotFoundException: If the fax number does not exist
            PermissionDeniedException: If the user cannot access the fax number
        """
        fax_number = await fax_numbers_service.get_one_or_none(id=fax_number_id)
        if fax_number is None:
            raise NotFoundException(detail="Fax number not found.")
        if not _can_access_fax_number(current_user, fax_number):
            raise PermissionDeniedException(detail="Insufficient permissions to access this fax number.")
        return fax_number

    @get(
        operation_id="ListFaxEmailRoutes",
        summary="List fax email routes",
        description="Retrieve a paginated list of email routes configured for a specific fax number. Supports filtering by email address, creation date, and update date.",
        path="",
        guards=[requires_feature_permission("fax_email_routes", "view"), requires_fax_number_access],
    )
    async def list_fax_email_routes(
        self,
        fax_email_routes_service: FaxEmailRouteService,
        fax_numbers_service: FaxNumberService,
        current_user: m.User,
        fax_number_id: UUID,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[FaxEmailRoute]:
        """List email routes for a fax number.

        Args:
            fax_email_routes_service: Fax Email Route Service
            fax_numbers_service: Fax Number Service
            current_user: Current User
            fax_number_id: Fax Number ID
            filters: Filters

        Returns:
            OffsetPagination[FaxEmailRoute]
        """
        await self._verify_fax_number_access(fax_numbers_service, current_user, fax_number_id)
        results, total = await fax_email_routes_service.list_and_count(
            *filters,
            m.FaxEmailRoute.fax_number_id == fax_number_id,
        )
        return fax_email_routes_service.to_schema(results, total, filters, schema_type=FaxEmailRoute)

    @post(
        operation_id="CreateFaxEmailRoute",
        summary="Create a fax email route",
        description="Add a new email routing rule to a fax number. The change is audit-logged and emits a fax_email_route_created event.",
        path="",
        guards=[requires_feature_permission("fax_email_routes", "edit"), requires_fax_number_access],
        status_code=HTTP_201_CREATED,
    )
    async def create_fax_email_route(
        self,
        request: Request[m.User, Token, Any],
        fax_email_routes_service: FaxEmailRouteService,
        fax_numbers_service: FaxNumberService,
        audit_service: AuditLogService,
        current_user: m.User,
        fax_number_id: UUID,
        data: FaxEmailRouteCreate,
    ) -> FaxEmailRoute:
        """Add an email route to a fax number.

        Args:
            request: The current request
            fax_email_routes_service: Fax Email Route Service
            fax_numbers_service: Fax Number Service
            audit_service: Audit Log Service
            current_user: Current User
            fax_number_id: Fax Number ID
            data: Email Route Create

        Returns:
            FaxEmailRoute
        """
        await self._verify_fax_number_access(fax_numbers_service, current_user, fax_number_id)
        payload = data.to_dict()
        payload["fax_number_id"] = fax_number_id
        db_obj = await fax_email_routes_service.create(payload)
        result = fax_email_routes_service.to_schema(db_obj, schema_type=FaxEmailRoute)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="fax.email_route.created",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="fax_email_route",
            target_id=db_obj.id,
            target_label=db_obj.email_address,
            before=None,
            after=after,
            request=request,
        )
        request.app.emit(event_id="fax_email_route_created", route_id=db_obj.id)
        return result

    @patch(
        operation_id="UpdateFaxEmailRoute",
        summary="Update a fax email route",
        description="Update an existing email route on a fax number. Validates that the route belongs to the specified fax number and records an audit log entry.",
        path="/{route_id:uuid}",
        guards=[requires_feature_permission("fax_email_routes", "edit"), requires_fax_number_access],
    )
    async def update_fax_email_route(
        self,
        request: Request[m.User, Token, Any],
        fax_email_routes_service: FaxEmailRouteService,
        fax_numbers_service: FaxNumberService,
        audit_service: AuditLogService,
        current_user: m.User,
        fax_number_id: UUID,
        route_id: Annotated[UUID, Parameter(title="Route ID", description="The email route to update.")],
        data: FaxEmailRouteUpdate,
    ) -> FaxEmailRoute:
        """Update an email route.

        Args:
            request: The current request
            fax_email_routes_service: Fax Email Route Service
            fax_numbers_service: Fax Number Service
            audit_service: Audit Log Service
            current_user: Current User
            fax_number_id: Fax Number ID
            route_id: Route ID
            data: Email Route Update

        Raises:
            HTTPException: If the route does not belong to this fax number

        Returns:
            FaxEmailRoute
        """
        await self._verify_fax_number_access(fax_numbers_service, current_user, fax_number_id)
        existing = await fax_email_routes_service.get(route_id)
        if existing.fax_number_id != fax_number_id:
            raise ClientException(detail="Route does not belong to this fax number.")
        before = capture_snapshot(existing)
        db_obj = await fax_email_routes_service.update(item_id=route_id, data=data.to_dict())
        result = fax_email_routes_service.to_schema(db_obj, schema_type=FaxEmailRoute)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="fax.email_route.updated",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="fax_email_route",
            target_id=route_id,
            target_label=db_obj.email_address,
            before=before,
            after=after,
            request=request,
        )
        request.app.emit(event_id="fax_email_route_updated", route_id=route_id)
        return result

    @delete(
        operation_id="DeleteFaxEmailRoute",
        summary="Delete a fax email route",
        description="Remove an email route from a fax number. Validates that the route belongs to the specified fax number and records an audit log entry.",
        path="/{route_id:uuid}",
        guards=[requires_feature_permission("fax_email_routes", "edit"), requires_fax_number_access],
        status_code=HTTP_204_NO_CONTENT,
        return_dto=None,
    )
    async def delete_fax_email_route(
        self,
        request: Request[m.User, Token, Any],
        fax_email_routes_service: FaxEmailRouteService,
        fax_numbers_service: FaxNumberService,
        audit_service: AuditLogService,
        current_user: m.User,
        fax_number_id: UUID,
        route_id: Annotated[UUID, Parameter(title="Route ID", description="The email route to delete.")],
    ) -> None:
        """Remove an email route.

        Args:
            request: The current request
            fax_email_routes_service: Fax Email Route Service
            fax_numbers_service: Fax Number Service
            audit_service: Audit Log Service
            current_user: Current User
            fax_number_id: Fax Number ID
            route_id: Route ID

        Raises:
            HTTPException: If the route does not belong to this fax number
        """
        await self._verify_fax_number_access(fax_numbers_service, current_user, fax_number_id)
        existing = await fax_email_routes_service.get(route_id)
        if existing.fax_number_id != fax_number_id:
            raise ClientException(detail="Route does not belong to this fax number.")
        before = capture_snapshot(existing)
        target_label = existing.email_address
        request.app.emit(event_id="fax_email_route_deleted", route_id=route_id)
        await fax_email_routes_service.delete(item_id=route_id)
        await log_audit(
            audit_service,
            action="fax.email_route.deleted",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="fax_email_route",
            target_id=route_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )
