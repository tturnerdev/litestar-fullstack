"""User Account Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT
from sqlalchemy.orm import joinedload, load_only, selectinload

from app.db import models as m
from app.domain.accounts.guards import requires_superuser
from app.domain.accounts.schemas import User, UserCreate, UserUpdate
from app.domain.accounts.services import UserService
from app.domain.admin.deps import provide_audit_log_service
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class UserController(Controller):
    """User Account Controller."""

    path = "/api/users"
    tags = ["User Accounts"]
    guards = [requires_superuser]
    dependencies = create_service_dependencies(
        UserService,
        key="users_service",
        load=[
            selectinload(m.User.roles).options(joinedload(m.UserRole.role, innerjoin=True)),
            selectinload(m.User.teams).options(
                joinedload(m.TeamMember.team, innerjoin=True).options(load_only(m.Team.name)),
            ),
            selectinload(m.User.oauth_accounts),
        ],
        filters={
            "id_filter": UUID,
            "search": "name,email",
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

    @get(
        operation_id="ListUsers",
        summary="List users",
        description="Return a paginated list of user accounts with their roles, team memberships, and linked OAuth accounts. Supports search by name or email, date range filtering on created_at/updated_at, and configurable sort order.",
    )
    async def list_users(
        self, users_service: UserService, filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)]
    ) -> OffsetPagination[User]:
        """List users.

        Args:
            filters: The filters to apply to the list of users.
            users_service: The user service.

        Returns:
            The list of users.
        """
        results, total = await users_service.list_and_count(*filters)
        return users_service.to_schema(results, total, filters, schema_type=User)

    @get(
        operation_id="GetUser",
        summary="Get user details",
        description="Retrieve a single user account by UUID, including their roles, team memberships, and linked OAuth accounts.",
        path="/{user_id:uuid}",
    )
    async def get_user(
        self,
        users_service: UserService,
        user_id: Annotated[UUID, Parameter(title="User ID", description="The user to retrieve.")],
    ) -> User:
        """Get a user.

        Args:
            user_id: The ID of the user to retrieve.
            users_service: The user service.

        Returns:
            The user.
        """
        db_obj = await users_service.get(user_id)
        return users_service.to_schema(db_obj, schema_type=User)

    @post(
        operation_id="CreateUser",
        summary="Create a user",
        description="Create a new user account with the supplied details. Records the creation in the audit log with a snapshot of the new record and emits a user_created event.",
        status_code=HTTP_201_CREATED,
    )
    async def create_user(
        self,
        request: Request[m.User, Token, Any],
        users_service: UserService,
        audit_service: AuditLogService,
        data: UserCreate,
    ) -> User:
        """Create a new user.

        Args:
            request: The incoming request.
            data: The data to create the user with.
            users_service: The user service.
            audit_service: The audit log service.

        Returns:
            The created user.
        """
        db_obj = await users_service.create(data.to_dict())
        await log_audit(
            audit_service,
            action="account.user.created",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="User",
            target_id=db_obj.id,
            target_label=db_obj.email,
            before=None,
            after=capture_snapshot(db_obj),
            request=request,
        )
        request.app.emit(event_id="user_created", user_id=db_obj.id)
        return users_service.to_schema(db_obj, schema_type=User)

    @patch(
        operation_id="UpdateUser",
        summary="Update a user",
        description="Update an existing user account's fields. Captures before/after snapshots, records the change in the audit log, and emits a user_updated event.",
        path="/{user_id:uuid}",
    )
    async def update_user(
        self,
        request: Request[m.User, Token, Any],
        data: UserUpdate,
        users_service: UserService,
        audit_service: AuditLogService,
        user_id: Annotated[UUID, Parameter(title="User ID", description="The user to update.")],
    ) -> User:
        """Update a user.

        Args:
            request: The incoming request.
            data: The data to update the user with.
            users_service: The user service.
            audit_service: The audit log service.
            user_id: The ID of the user to update.

        Returns:
            The updated user.
        """
        db_obj = await users_service.get(user_id)
        before = capture_snapshot(db_obj)
        db_obj = await users_service.update(item_id=user_id, data=data.to_dict())
        request.app.emit(event_id="user_updated", user_id=db_obj.id)
        await log_audit(
            audit_service,
            action="account.user.updated",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="User",
            target_id=db_obj.id,
            target_label=db_obj.email,
            before=before,
            after=capture_snapshot(db_obj),
            request=request,
        )
        return users_service.to_schema(db_obj, schema_type=User)

    @delete(
        operation_id="DeleteUser",
        summary="Delete a user",
        description="Permanently remove a user account from the system. Captures a before snapshot, emits a user_deleted event, deletes the record, and records the deletion in the audit log.",
        path="/{user_id:uuid}",
        status_code=HTTP_204_NO_CONTENT,
        return_dto=None,
    )
    async def delete_user(
        self,
        request: Request[m.User, Token, Any],
        users_service: UserService,
        audit_service: AuditLogService,
        user_id: Annotated[UUID, Parameter(title="User ID", description="The user to delete.")],
    ) -> None:
        """Delete a user from the system.

        Args:
            request: The incoming request.
            user_id: The ID of the user to delete.
            users_service: The user service.
            audit_service: The audit log service.
        """
        db_obj = await users_service.get(user_id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.email
        request.app.emit(event_id="user_deleted", user_id=user_id)
        _ = await users_service.delete(user_id)
        await log_audit(
            audit_service,
            action="account.user.deleted",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="User",
            target_id=user_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )
