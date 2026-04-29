"""User Profile Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog
from litestar import Controller, Request, delete, get, patch
from litestar.di import Provide

from app.domain.accounts.deps import provide_users_service
from app.domain.accounts.schemas import PasswordUpdate, ProfileUpdate, User
from app.domain.admin.deps import provide_audit_log_service
from app.lib.audit import capture_snapshot, log_audit
from app.lib.schema import Message

if TYPE_CHECKING:
    from litestar.security.jwt import Token

    from app.db import models as m
    from app.domain.accounts.services import UserService
    from app.domain.admin.services import AuditLogService

logger = structlog.get_logger()


class ProfileController(Controller):
    """Handles the current user profile operations."""

    tags = ["Access"]
    dependencies = {
        "users_service": Provide(provide_users_service),
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(
        operation_id="AccountProfile",
        path="/api/me",
        summary="User Profile",
        description="User profile information.",
    )
    async def get_profile(self, users_service: UserService, current_user: m.User) -> User:
        """User profile.

        Returns:
            User: The current user's profile.
        """
        return users_service.to_schema(current_user, schema_type=User)

    @patch(operation_id="AccountProfileUpdate", path="/api/me")
    async def update_profile(
        self,
        request: Request[m.User, Token, Any],
        current_user: m.User,
        data: ProfileUpdate,
        users_service: UserService,
        audit_service: AuditLogService,
    ) -> User:
        """User Profile.

        Args:
            request: The HTTP request.
            current_user: The current user.
            data: The profile update data.
            users_service: The users service.
            audit_service: Audit log service.

        Returns:
            The response object.
        """
        before = capture_snapshot(current_user)
        db_obj = await users_service.update(data, item_id=current_user.id)
        after = capture_snapshot(db_obj)

        await log_audit(
            audit_service,
            action="account.profile_update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="user",
            target_id=current_user.id,
            target_label=current_user.email,
            before=before,
            after=after,
            request=request,
        )

        return users_service.to_schema(db_obj, schema_type=User)

    @patch(operation_id="AccountPasswordUpdate", path="/api/me/password")
    async def update_password(
        self,
        request: Request[m.User, Token, Any],
        current_user: m.User,
        data: PasswordUpdate,
        users_service: UserService,
        audit_service: AuditLogService,
    ) -> Message:
        """Update user password.

        Args:
            request: The HTTP request.
            current_user: The current user.
            data: The password update data.
            users_service: The users service.
            audit_service: Audit log service.

        Returns:
            The response object.
        """
        await users_service.update_password(data.to_dict(), db_obj=current_user)

        await log_audit(
            audit_service,
            action="account.password_change",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="user",
            target_id=current_user.id,
            target_label=current_user.email,
            request=request,
        )

        return Message(message="Your password was successfully modified.")

    @delete(operation_id="AccountDelete", path="/api/me")
    async def remove_account(
        self,
        request: Request[m.User, Token, Any],
        current_user: m.User,
        users_service: UserService,
        audit_service: AuditLogService,
    ) -> None:
        """Remove your account.

        Args:
            request: The HTTP request.
            current_user: The current user.
            users_service: The users service.
            audit_service: Audit log service.
        """
        before = capture_snapshot(current_user)
        _ = await users_service.delete(current_user.id)

        await log_audit(
            audit_service,
            action="account.delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="user",
            target_id=current_user.id,
            target_label=current_user.email,
            before=before,
            after=None,
            request=request,
        )
