"""User Profile Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog
from litestar import Controller, Request, delete, get, patch
from litestar.di import Provide

from app.domain.accounts.deps import provide_users_service
from app.domain.accounts.schemas import PasswordUpdate, ProfileUpdate, SecurityActivityEntry, User
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

    # Security-relevant actions shown on the user's profile page.
    _SECURITY_ACTIONS: frozenset[str] = frozenset({
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
    })

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
