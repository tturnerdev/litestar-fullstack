"""Email Verification Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar import Controller, Request, get, post
from litestar.di import Provide
from litestar.status_codes import HTTP_200_OK, HTTP_201_CREATED

from app.domain.accounts.deps import provide_email_verification_service, provide_users_service
from app.domain.accounts.schemas import (
    EmailVerificationConfirm,
    EmailVerificationRequest,
    EmailVerificationSent,
    EmailVerificationStatus,
    User,
)
from app.domain.admin.deps import provide_audit_log_service
from app.lib.audit import log_audit

if TYPE_CHECKING:
    from uuid import UUID

    from litestar.security.jwt import Token

    from app.db import models as m
    from app.domain.accounts.services import EmailVerificationTokenService, UserService
    from app.domain.admin.services import AuditLogService
    from app.lib.email import AppEmailService


class EmailVerificationController(Controller):
    """Email verification operations."""

    path = "/api/email-verification"
    tags = ["Access"]
    dependencies = {
        "users_service": Provide(provide_users_service),
        "verification_service": Provide(provide_email_verification_service),
        "audit_service": Provide(provide_audit_log_service),
    }

    @post("/request", status_code=HTTP_201_CREATED)
    async def request_verification(
        self,
        users_service: UserService,
        app_mailer: AppEmailService,
        request: Request[m.User, Token, Any],
        data: EmailVerificationRequest,
    ) -> EmailVerificationSent:
        """Request email verification for a user.

        Returns:
            Response indicating the verification email has been sent.
        """
        user = await users_service.get_one_or_none(email=data.email)
        if user is None:
            return EmailVerificationSent(message="If the email exists, a verification link has been sent")
        if user.is_verified:
            return EmailVerificationSent(message="Email is already verified")
        request.app.emit(event_id="verification_requested", user_id=user.id, mailer=app_mailer)
        return EmailVerificationSent(message="Verification email sent")

    @post("/verify", status_code=HTTP_200_OK)
    async def verify_email(
        self,
        request: Request[m.User, Token, Any],
        data: EmailVerificationConfirm,
        users_service: UserService,
        verification_service: EmailVerificationTokenService,
        audit_service: AuditLogService,
    ) -> User:
        """Verify email using verification token.

        Returns:
            The verified user object.
        """
        verification_token = await verification_service.verify_token(data.token)
        user = await users_service.verify_email(user_id=verification_token.user_id, email=verification_token.email)

        await log_audit(
            audit_service,
            action="account.email.verified",
            actor_id=user.id,
            actor_email=user.email,
            target_type="user",
            target_id=user.id,
            target_label=user.email,
            request=request,
        )

        return users_service.to_schema(user, schema_type=User)

    @get("/status/{user_id:uuid}")
    async def get_verification_status(
        self,
        user_id: UUID,
        users_service: UserService,
    ) -> EmailVerificationStatus:
        """Get email verification status for a user.

        Returns:
            Status object indicating if the email is verified.
        """
        is_verified = await users_service.is_email_verified(user_id)
        return EmailVerificationStatus(is_verified=is_verified)
