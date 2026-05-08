"""Role Controllers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.datastructures import CacheControlHeader
from litestar.di import Provide
from litestar.exceptions import ClientException, NotFoundException
from litestar.params import Dependency, Parameter
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT

from app.db import models as m
from app.domain.accounts.guards import requires_superuser
from app.domain.accounts.schemas import Message, Role, RoleCreate, RoleUpdate, UserRoleAdd, UserRoleRevoke
from app.domain.accounts.services import RoleService, UserRoleService, UserService
from app.domain.admin.deps import provide_audit_log_service
from app.lib.audit import capture_snapshot, log_audit
from app.lib.constants import DEFAULT_ACCESS_ROLE, SUPERUSER_ACCESS_ROLE
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class RoleController(Controller):
    """Handles the interactions within the Role objects."""

    path = "/api/roles"
    tags = ["Roles"]
    guards = [requires_superuser]
    dependencies = {
        **create_service_dependencies(
            RoleService,
            key="roles_service",
            load=[m.Role.users],
            filters={
                "id_filter": UUID,
                "pagination_type": "limit_offset",
                "pagination_size": 50,
                "sort_field": "name",
                "search": "name,slug",
            },
        ),
        **create_service_dependencies(UserService, key="users_service"),
        **create_service_dependencies(UserRoleService, key="user_roles_service"),
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(
        operation_id="ListRoles",
        summary="List roles",
        cache=300,
        cache_control=CacheControlHeader(private=True, max_age=300),
    )
    async def list_roles(
        self,
        roles_service: RoleService,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[Role]:
        """List roles.

        Args:
            filters: The filters to apply to the list of roles.
            roles_service: The role service.

        Returns:
            The list of roles.
        """
        results, total = await roles_service.list_and_count(*filters)
        return roles_service.to_schema(results, total, filters, schema_type=Role)

    @get(operation_id="GetRole", summary="Get role details", path="/{role_id:uuid}")
    async def get_role(
        self,
        roles_service: RoleService,
        role_id: Annotated[UUID, Parameter(title="Role ID", description="The role to retrieve.")],
    ) -> Role:
        """Get a role.

        Args:
            role_id: The ID of the role to retrieve.
            roles_service: The role service.

        Returns:
            The role.
        """
        db_obj = await roles_service.get(role_id)
        return roles_service.to_schema(db_obj, schema_type=Role)

    @post(operation_id="CreateRole", summary="Create a role", path="", status_code=HTTP_201_CREATED)
    async def create_role(
        self,
        request: Request[m.User, Token, Any],
        roles_service: RoleService,
        audit_service: AuditLogService,
        data: RoleCreate,
    ) -> Role:
        """Create a new role.

        Args:
            request: The incoming request.
            data: The data to create the role with.
            roles_service: The role service.
            audit_service: The audit log service.

        Returns:
            The created role.
        """
        db_obj = await roles_service.create(data.to_dict())
        await log_audit(
            audit_service,
            action="account.role.created",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="Role",
            target_id=db_obj.id,
            target_label=db_obj.name,
            before=None,
            after=capture_snapshot(db_obj),
            request=request,
        )
        request.app.emit(event_id="role_created", entity_id=db_obj.id)
        return roles_service.to_schema(db_obj, schema_type=Role)

    @patch(operation_id="UpdateRole", summary="Update a role", path="/{role_id:uuid}")
    async def update_role(
        self,
        request: Request[m.User, Token, Any],
        roles_service: RoleService,
        audit_service: AuditLogService,
        data: RoleUpdate,
        role_id: Annotated[UUID, Parameter(title="Role ID", description="The role to update.")],
    ) -> Role:
        """Update a role.

        Args:
            request: The incoming request.
            data: The data to update the role with.
            role_id: The ID of the role to update.
            roles_service: The role service.
            audit_service: The audit log service.

        Raises:
            HTTPException: If the role is a default role.

        Returns:
            The updated role.
        """
        if data.name in {DEFAULT_ACCESS_ROLE, SUPERUSER_ACCESS_ROLE}:
            raise ClientException(detail="Cannot update default roles")
        db_obj = await roles_service.get(role_id)
        before = capture_snapshot(db_obj)
        db_obj = await roles_service.update(item_id=role_id, data=data.to_dict())
        request.app.emit(event_id="role_updated", entity_id=db_obj.id)
        await log_audit(
            audit_service,
            action="account.role.updated",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="Role",
            target_id=db_obj.id,
            target_label=db_obj.name,
            before=before,
            after=capture_snapshot(db_obj),
            request=request,
        )
        return roles_service.to_schema(db_obj, schema_type=Role)

    @delete(operation_id="DeleteRole", summary="Delete a role", path="/{role_id:uuid}", status_code=HTTP_204_NO_CONTENT, return_dto=None)
    async def delete_role(
        self,
        request: Request[m.User, Token, Any],
        roles_service: RoleService,
        audit_service: AuditLogService,
        role_id: Annotated[UUID, Parameter(title="Role ID", description="The role to delete.")],
    ) -> None:
        """Delete a role.

        Args:
            request: The incoming request.
            role_id: The ID of the role to delete.
            roles_service: The role service.
            audit_service: The audit log service.

        Raises:
            HTTPException: If the role is a default role.
        """
        db_obj = await roles_service.get(role_id)
        if db_obj.name in {DEFAULT_ACCESS_ROLE, SUPERUSER_ACCESS_ROLE}:
            raise ClientException(detail="Cannot delete default roles")
        before = capture_snapshot(db_obj)
        target_label = db_obj.name
        request.app.emit(event_id="role_deleted", entity_id=role_id)
        _ = await roles_service.delete(role_id)
        await log_audit(
            audit_service,
            action="account.role.deleted",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="Role",
            target_id=role_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )

    @post(operation_id="AssignRole", summary="Assign a role to a user", path="/{role_slug:str}/assign")
    async def assign_role(
        self,
        request: Request[m.User, Token, Any],
        roles_service: RoleService,
        users_service: UserService,
        user_roles_service: UserRoleService,
        audit_service: AuditLogService,
        data: UserRoleAdd,
        role_slug: Annotated[str, Parameter(title="Role Slug", description="The role slug to assign.")],
    ) -> Message:
        """Assign a role to a user.

        Args:
            request: The incoming request.
            roles_service: The role service.
            users_service: The user service.
            user_roles_service: The user role service.
            audit_service: The audit log service.
            data: The user to assign the role to.
            role_slug: The slug of the role to assign.

        Returns:
            A message confirming the assignment.

        Raises:
            NotFoundException: If the role or user is not found.
            HTTPException: If the user already has the role.
        """
        role = await roles_service.get_one_or_none(slug=role_slug)
        if role is None:
            raise NotFoundException(detail=f"Role '{role_slug}' not found")

        user = await users_service.get_one_or_none(email=data.user_name)
        if user is None:
            raise NotFoundException(detail=f"User '{data.user_name}' not found")

        existing_role = await user_roles_service.get_one_or_none(user_id=user.id, role_id=role.id)
        if existing_role is not None:
            raise ClientException(detail=f"User '{data.user_name}' already has role '{role_slug}'", status_code=409)

        db_obj = await user_roles_service.create(
            data={
                "user_id": user.id,
                "role_id": role.id,
                "assigned_at": datetime.now(UTC),
            },
        )
        request.app.emit(event_id="user_role_assigned", entity_id=db_obj.id)
        await log_audit(
            audit_service,
            action="account.role.assigned",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="Role",
            target_id=role.id,
            target_label=role.name,
            before=None,
            after=capture_snapshot(db_obj),
            request=request,
            metadata={"user_email": data.user_name, "role_slug": role_slug},
        )

        return Message(message=f"Successfully assigned the '{role_slug}' role to {data.user_name}.")

    @post(operation_id="RevokeRole", summary="Revoke a role from a user", path="/{role_slug:str}/revoke")
    async def revoke_role(
        self,
        request: Request[m.User, Token, Any],
        roles_service: RoleService,
        users_service: UserService,
        user_roles_service: UserRoleService,
        audit_service: AuditLogService,
        data: UserRoleRevoke,
        role_slug: Annotated[str, Parameter(title="Role Slug", description="The role slug to revoke.")],
    ) -> Message:
        """Revoke a role from a user.

        Args:
            request: The incoming request.
            roles_service: The role service.
            users_service: The user service.
            user_roles_service: The user role service.
            audit_service: The audit log service.
            data: The user to revoke the role from.
            role_slug: The slug of the role to revoke.

        Returns:
            A message confirming the revocation.

        Raises:
            NotFoundException: If the role or user is not found, or if the user doesn't have the role.
        """
        role = await roles_service.get_one_or_none(slug=role_slug)
        if role is None:
            raise NotFoundException(detail=f"Role '{role_slug}' not found")

        user = await users_service.get_one_or_none(email=data.user_name)
        if user is None:
            raise NotFoundException(detail=f"User '{data.user_name}' not found")

        existing_role = await user_roles_service.get_one_or_none(user_id=user.id, role_id=role.id)
        if existing_role is None:
            raise NotFoundException(detail=f"User '{data.user_name}' does not have role '{role_slug}'")

        before = capture_snapshot(existing_role)
        request.app.emit(event_id="user_role_revoked", entity_id=existing_role.id)
        await user_roles_service.delete(existing_role.id)
        await log_audit(
            audit_service,
            action="account.role.revoked",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="Role",
            target_id=role.id,
            target_label=role.name,
            before=before,
            after=None,
            request=request,
            metadata={"user_email": data.user_name, "role_slug": role_slug},
        )

        return Message(message=f"Successfully revoked the '{role_slug}' role from {data.user_name}.")
