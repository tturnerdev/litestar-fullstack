"""Tests for account domain schema validation logic."""

from __future__ import annotations

import msgspec
import pytest

from app.domain.accounts.schemas._auth import AccountLogin, AccountRegister, PasswordUpdate
from app.domain.accounts.schemas._email_verification import EmailVerificationRequest
from app.domain.accounts.schemas._mfa import MfaChallenge
from app.domain.accounts.schemas._password_reset import ForgotPasswordRequest, ResetPasswordRequest
from app.domain.accounts.schemas._user import ProfileUpdate, UserCreate, UserTeam, UserUpdate
from app.lib.validation import PasswordValidationError, ValidationError


class TestAccountLogin:
    def test_valid(self) -> None:
        login = AccountLogin(username="user@example.com", password="anything")
        assert login.username == "user@example.com"

    def test_normalizes_email(self) -> None:
        login = AccountLogin(username="USER@Example.COM", password="anything")
        assert login.username == "user@example.com"

    def test_invalid_email_raises(self) -> None:
        with pytest.raises(ValidationError):
            AccountLogin(username="not-an-email", password="x")


class TestAccountRegister:
    def test_valid_minimal(self) -> None:
        reg = AccountRegister(
            email="new@example.com",
            password="SecureP@ss123!",
        )
        assert reg.email == "new@example.com"

    def test_valid_with_name_and_username(self) -> None:
        reg = AccountRegister(
            email="new@example.com",
            password="SecureP@ss123!",
            name="John Doe",
            username="johndoe",
        )
        assert reg.name == "John Doe"
        assert reg.username == "johndoe"

    def test_invalid_email(self) -> None:
        with pytest.raises(ValidationError):
            AccountRegister(email="bad", password="SecureP@ss123!")

    def test_weak_password(self) -> None:
        with pytest.raises((ValidationError, PasswordValidationError)):
            AccountRegister(email="user@example.com", password="weak")

    def test_invalid_name(self) -> None:
        with pytest.raises(ValidationError):
            AccountRegister(
                email="user@example.com",
                password="SecureP@ss123!",
                name="<script>",
            )


class TestPasswordUpdate:
    def test_valid(self) -> None:
        pu = PasswordUpdate(
            current_password="old",
            new_password="NewSecureP@ss1!",
        )
        assert pu.new_password == "NewSecureP@ss1!"

    def test_weak_new_password(self) -> None:
        with pytest.raises((ValidationError, PasswordValidationError)):
            PasswordUpdate(current_password="old", new_password="short")


class TestMfaChallenge:
    def test_code_only(self) -> None:
        c = MfaChallenge(code="123456")
        assert c.code == "123456"
        assert c.recovery_code is None

    def test_recovery_only(self) -> None:
        c = MfaChallenge(recovery_code="ABCD1234")
        assert c.recovery_code == "ABCD1234"
        assert c.code is None

    def test_neither_raises(self) -> None:
        with pytest.raises(ValueError, match="must be provided"):
            MfaChallenge()

    def test_both_raises(self) -> None:
        with pytest.raises(ValueError, match="not both"):
            MfaChallenge(code="123456", recovery_code="ABCD1234")


class TestUserCreate:
    def test_valid_minimal(self) -> None:
        u = UserCreate(email="user@example.com", password="SecureP@ss123!")
        assert u.email == "user@example.com"

    def test_valid_with_optional_fields(self) -> None:
        u = UserCreate(
            email="user@example.com",
            password="SecureP@ss123!",
            name="Jane Doe",
            username="janedoe",
            phone="+15551234567",
        )
        assert u.name == "Jane Doe"
        assert u.username == "janedoe"
        assert u.phone == "+15551234567"

    def test_username_equals_email_local_part_raises(self) -> None:
        with pytest.raises(ValueError, match="same as email local part"):
            UserCreate(
                email="johndoe@example.com",
                password="SecureP@ss123!",
                username="johndoe",
            )

    def test_invalid_phone(self) -> None:
        with pytest.raises(ValidationError):
            UserCreate(
                email="user@example.com",
                password="SecureP@ss123!",
                phone="abc",
            )


class TestUserUpdate:
    def test_all_unset_raises(self) -> None:
        with pytest.raises(ValueError, match="At least one field"):
            UserUpdate()

    def test_single_field(self) -> None:
        u = UserUpdate(is_active=False)
        assert u.is_active is False
        assert u.email is msgspec.UNSET

    def test_validates_email(self) -> None:
        with pytest.raises(ValidationError):
            UserUpdate(email="bad")

    def test_validates_name(self) -> None:
        with pytest.raises(ValidationError):
            UserUpdate(name="<script>")

    def test_valid_email_update(self) -> None:
        u = UserUpdate(email="NEW@Example.COM")
        assert u.email == "new@example.com"


class TestProfileUpdate:
    def test_validates_name(self) -> None:
        p = ProfileUpdate(name="Jane Doe")
        assert p.name == "Jane Doe"

    def test_invalid_name(self) -> None:
        with pytest.raises(ValidationError):
            ProfileUpdate(name="<script>")

    def test_validates_username(self) -> None:
        p = ProfileUpdate(username="janedoe")
        assert p.username == "janedoe"

    def test_validates_phone(self) -> None:
        p = ProfileUpdate(phone="+15551234567")
        assert p.phone == "+15551234567"


class TestForgotPasswordRequest:
    def test_valid(self) -> None:
        r = ForgotPasswordRequest(email="user@example.com")
        assert r.email == "user@example.com"

    def test_invalid_email(self) -> None:
        with pytest.raises(ValidationError):
            ForgotPasswordRequest(email="bad")


class TestResetPasswordRequest:
    def test_valid(self) -> None:
        r = ResetPasswordRequest(
            token="abc",
            password="SecureP@ss123!",
            password_confirm="SecureP@ss123!",
        )
        assert r.password == "SecureP@ss123!"

    def test_mismatch_raises(self) -> None:
        with pytest.raises(ValueError, match="do not match"):
            ResetPasswordRequest(
                token="abc",
                password="SecureP@ss123!",
                password_confirm="DifferentP@ss1!",
            )

    def test_weak_password(self) -> None:
        with pytest.raises((ValidationError, PasswordValidationError)):
            ResetPasswordRequest(token="abc", password="weak", password_confirm="weak")


class TestEmailVerificationRequest:
    def test_valid(self) -> None:
        r = EmailVerificationRequest(email="user@example.com")
        assert r.email == "user@example.com"

    def test_invalid_email(self) -> None:
        with pytest.raises(ValidationError):
            EmailVerificationRequest(email="bad")


class TestUserTeam:
    def test_default_role(self) -> None:
        from uuid import uuid4

        from app.db.models._team_roles import TeamRoles

        t = UserTeam(team_id=uuid4(), team_name="Team")
        assert t.role == TeamRoles.MEMBER

    def test_explicit_role(self) -> None:
        from uuid import uuid4

        from app.db.models._team_roles import TeamRoles

        t = UserTeam(team_id=uuid4(), team_name="Team", role=TeamRoles.ADMIN)
        assert t.role == TeamRoles.ADMIN
