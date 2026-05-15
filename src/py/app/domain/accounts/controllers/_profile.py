"""User Profile Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any

import structlog
from litestar import Controller, Request, delete, get, patch, put
from litestar.datastructures import (
    UploadFile,  # noqa: TC002  (resolved at runtime by Litestar for the request signature)
)
from litestar.di import Provide
from litestar.enums import RequestEncodingType
from litestar.params import Body
from litestar.status_codes import HTTP_204_NO_CONTENT

from app.db import models as m
from app.domain.accounts.deps import provide_users_service
from app.domain.accounts.guards import requires_active_user
from app.domain.accounts.schemas import PasswordUpdate, ProfileUpdate, SecurityActivityEntry, User
from app.domain.admin.deps import provide_audit_log_service
from app.domain.attachments.services import AttachmentService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_provider
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
    guards = [requires_active_user]
    dependencies = {
        "users_service": Provide(provide_users_service),
        "attachments_service": create_service_provider(AttachmentService),
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

    # Security-relevant actions shown on the user's profile page.
    _SECURITY_ACTIONS: frozenset[str] = frozenset(
        {
            "account.login",
            "account.logout",
            "account.password_change",
            "account.password_reset",
            "account.session_revoke",
            "account.sessions_revoke_all",
            "account.profile_update",
            "account.oauth_unlink",
            "account.email.verified",
            "account.register",
            "account.delete",
            "account.oauth.linked",
            "account.oauth.upgraded",
            "mfa.setup.confirmed",
            "mfa.setup.failed",
            "mfa.disabled",
            "mfa.disabled.oauth",
            "mfa.challenge.success",
            "mfa.challenge.failed",
            "mfa.backup_codes.regenerated",
        }
    )

    # Human-readable labels for security actions.
    _ACTION_LABELS: dict[str, str] = {
        "account.login": "Signed in",
        "account.logout": "Signed out",
        "account.password_change": "Password changed",
        "account.password_reset": "Password reset via email",
        "account.session_revoke": "Session revoked",
        "account.sessions_revoke_all": "All other sessions revoked",
        "account.profile_update": "Profile information updated",
        "account.oauth_unlink": "OAuth account unlinked",
        "account.email.verified": "Email address verified",
        "account.register": "Account registered",
        "account.delete": "Account deleted",
        "account.oauth.linked": "OAuth account linked",
        "account.oauth.upgraded": "Account upgraded via OAuth",
        "mfa.setup.confirmed": "Two-factor authentication enabled",
        "mfa.setup.failed": "Two-factor setup attempt failed",
        "mfa.disabled": "Two-factor authentication disabled",
        "mfa.disabled.oauth": "Two-factor disabled (OAuth migration)",
        "mfa.challenge.success": "Two-factor challenge passed",
        "mfa.challenge.failed": "Two-factor challenge failed",
        "mfa.backup_codes.regenerated": "Backup codes regenerated",
    }

    @get(
        operation_id="GetSecurityActivity",
        path="/api/me/security-activity",
        summary="Recent Security Activity",
        description="Returns the current user's recent security-relevant audit events.",
    )
    async def get_security_activity(
        self,
        current_user: m.User,
        audit_service: AuditLogService,
    ) -> list[SecurityActivityEntry]:
        """Return the 10 most recent security events for the current user.

        Queries the audit log for events where the current user is the actor,
        filtered to security-relevant actions only.

        Args:
            current_user: The authenticated user.
            audit_service: Audit log service.

        Returns:
            List of recent security activity entries.
        """
        from sqlalchemy import desc

        from app.db.models import AuditLog

        results = await audit_service.list(
            AuditLog.actor_id == current_user.id,
            AuditLog.action.in_(self._SECURITY_ACTIONS),
            order_by=[desc(AuditLog.created_at)],
            limit=10,
        )

        return [
            SecurityActivityEntry(
                id=entry.id,
                action=entry.action,
                description=self._ACTION_LABELS.get(entry.action, entry.action),
                created_at=entry.created_at,
                ip_address=entry.ip_address,
            )
            for entry in results
        ]

    @patch(
        operation_id="AccountProfileUpdate",
        summary="Update profile",
        description="Update the authenticated user's profile fields (e.g. name, avatar). Captures before/after snapshots, records the change in the audit log, and emits a user_updated event.",
        path="/api/me",
    )
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

        result = users_service.to_schema(db_obj, schema_type=User)

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
        request.app.emit(event_id="user_updated", user_id=current_user.id)

        return result

    @patch(
        operation_id="AccountPasswordUpdate",
        summary="Update password",
        description="Change the authenticated user's password after verifying the current password. Records the password change in the audit log.",
        path="/api/me/password",
    )
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

    @put(operation_id="AccountAvatarSet", path="/api/me/avatar")
    async def set_avatar(
        self,
        current_user: m.User,
        users_service: UserService,
        attachments_service: AttachmentService,
        audit_service: AuditLogService,
        data: Annotated[UploadFile, Body(media_type=RequestEncodingType.MULTI_PART)],
    ) -> User:
        """Upload and set the current user's avatar.

        Args:
            current_user: The current user.
            users_service: The users service.
            attachments_service: The attachments service.
            audit_service: The audit log service.
            data: The uploaded image.

        Returns:
            The updated user profile.
        """
        previous_avatar_id = current_user.avatar_id
        attachment = await attachments_service.create_from_upload(
            data,
            uploaded_by_id=current_user.id,
            purpose=m.AttachmentPurpose.AVATAR,
            excluding_attachment_id=previous_avatar_id,
        )
        db_obj = await users_service.update(
            {"avatar_id": attachment.id, "avatar_url": f"/api/uploads/{attachment.id}/content"},
            item_id=current_user.id,
        )
        if previous_avatar_id and previous_avatar_id != attachment.id:
            previous = await attachments_service.get_one_or_none(id=previous_avatar_id)
            if previous is not None:
                await attachments_service.delete_with_object(previous)
        await audit_service.log_action(
            "user.avatar.set",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="user",
            target_id=str(current_user.id),
            target_label=current_user.email,
            details={"attachment_id": str(attachment.id), "size_bytes": attachment.size_bytes},
        )
        return users_service.to_schema(db_obj, schema_type=User)

    @delete(operation_id="AccountAvatarClear", path="/api/me/avatar", status_code=200)
    async def clear_avatar(
        self,
        current_user: m.User,
        users_service: UserService,
        attachments_service: AttachmentService,
        audit_service: AuditLogService,
    ) -> User:
        """Remove the current user's avatar.

        Args:
            current_user: The current user.
            users_service: The users service.
            attachments_service: The attachments service.
            audit_service: The audit log service.

        Returns:
            The updated user profile.
        """
        previous_avatar_id = current_user.avatar_id
        db_obj = await users_service.update({"avatar_id": None, "avatar_url": None}, item_id=current_user.id)
        if previous_avatar_id:
            previous = await attachments_service.get_one_or_none(id=previous_avatar_id)
            if previous is not None:
                await attachments_service.delete_with_object(previous)
        await audit_service.log_action(
            "user.avatar.cleared",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="user",
            target_id=str(current_user.id),
            target_label=current_user.email,
        )
        return users_service.to_schema(db_obj, schema_type=User)

    @delete(
        operation_id="AccountDelete",
        summary="Delete account",
        description="Permanently delete the authenticated user's account. Captures a before snapshot, emits a user_deleted event, removes the user record, and records the deletion in the audit log.",
        path="/api/me",
        status_code=HTTP_204_NO_CONTENT,
        return_dto=None,
    )
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
        request.app.emit(event_id="user_deleted", user_id=current_user.id)
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
