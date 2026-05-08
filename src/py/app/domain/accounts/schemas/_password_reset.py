"""Password reset schemas."""

from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct
from app.lib.validation import validate_email, validate_password


class ForgotPasswordRequest(msgspec.Struct, gc=False, omit_defaults=True):
    """Request to initiate password reset flow."""

    email: Annotated[str, Meta(min_length=1, max_length=255)]

    def __post_init__(self) -> None:
        """Validate email."""
        self.email = validate_email(self.email)


class PasswordResetSent(CamelizedBaseStruct):
    """Confirmation that password reset email was sent."""

    message: str
    expires_in_minutes: int = 60


class ValidateResetTokenRequest(msgspec.Struct, gc=False, omit_defaults=True):
    """Request to validate a reset token."""

    token: Annotated[str, Meta(min_length=1, max_length=255)]


class ResetTokenValidation(CamelizedBaseStruct):
    """Result of reset token validation."""

    valid: bool
    user_id: UUID | None = None
    expires_at: str | None = None


class ResetPasswordRequest(msgspec.Struct, gc=False, omit_defaults=True):
    """Request to reset password with token."""

    token: Annotated[str, Meta(min_length=1, max_length=255)]
    password: Annotated[str, Meta(min_length=1, max_length=255)]
    password_confirm: Annotated[str, Meta(min_length=1, max_length=255)]

    def __post_init__(self) -> None:
        """Validate passwords match and password strength."""
        if self.password != self.password_confirm:
            msg = "Passwords do not match"
            raise ValueError(msg)
        self.password = validate_password(self.password)


class PasswordResetComplete(CamelizedBaseStruct):
    """Confirmation that password was reset successfully."""

    message: str
    user_id: UUID
