"""Unit tests for voice domain guard functions.

Tests permission checking logic for:
- requires_extension_ownership: superuser bypass, role-based bypass, denial
- requires_phone_number_access: superuser bypass, role-based bypass, denial
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest
from litestar.exceptions import PermissionDeniedException

from app.domain.voice.guards import requires_extension_ownership, requires_phone_number_access
from app.lib import constants

pytestmark = [pytest.mark.unit, pytest.mark.security]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_role(role_name: str) -> Mock:
    """Build a mock assigned role object."""
    role = Mock()
    role.role_name = role_name
    return role


def _make_connection(
    *,
    is_superuser: bool = False,
    roles: list[Mock] | None = None,
) -> Mock:
    """Build a mock ASGIConnection with user attributes."""
    connection = Mock()
    connection.user.is_superuser = is_superuser
    connection.user.roles = roles if roles is not None else []
    return connection


def _make_handler() -> Mock:
    """Build a mock BaseRouteHandler."""
    return Mock()


# ---------------------------------------------------------------------------
# requires_extension_ownership
# ---------------------------------------------------------------------------


class TestRequiresExtensionOwnership:
    """Tests for the requires_extension_ownership guard."""

    def test_superuser_bypasses_guard(self) -> None:
        """Superuser should pass without checking roles."""
        connection = _make_connection(is_superuser=True)
        handler = _make_handler()

        # Should not raise
        requires_extension_ownership(connection, handler)

    def test_system_role_bypasses_guard(self) -> None:
        """User with SUPERUSER_ACCESS_ROLE should pass."""
        role = _make_role(constants.SUPERUSER_ACCESS_ROLE)
        connection = _make_connection(is_superuser=False, roles=[role])
        handler = _make_handler()

        # Should not raise
        requires_extension_ownership(connection, handler)

    def test_regular_user_denied(self) -> None:
        """Regular user without superuser or system role should be denied."""
        connection = _make_connection(is_superuser=False)
        handler = _make_handler()

        with pytest.raises(PermissionDeniedException) as exc_info:
            requires_extension_ownership(connection, handler)

        assert "extension" in str(exc_info.value.detail).lower()

    def test_user_with_non_matching_role_denied(self) -> None:
        """User with roles that do not match SUPERUSER_ACCESS_ROLE should be denied."""
        role = _make_role("viewer")
        connection = _make_connection(is_superuser=False, roles=[role])
        handler = _make_handler()

        with pytest.raises(PermissionDeniedException):
            requires_extension_ownership(connection, handler)

    def test_user_with_multiple_roles_one_matching(self) -> None:
        """User with multiple roles where one matches should pass."""
        roles = [
            _make_role("viewer"),
            _make_role(constants.SUPERUSER_ACCESS_ROLE),
            _make_role("editor"),
        ]
        connection = _make_connection(is_superuser=False, roles=roles)
        handler = _make_handler()

        # Should not raise
        requires_extension_ownership(connection, handler)

    def test_user_with_multiple_non_matching_roles_denied(self) -> None:
        """User with multiple roles but none matching should be denied."""
        roles = [_make_role("viewer"), _make_role("editor")]
        connection = _make_connection(is_superuser=False, roles=roles)
        handler = _make_handler()

        with pytest.raises(PermissionDeniedException):
            requires_extension_ownership(connection, handler)

    def test_user_with_empty_roles_denied(self) -> None:
        """User with an empty roles list should be denied."""
        connection = _make_connection(is_superuser=False, roles=[])
        handler = _make_handler()

        with pytest.raises(PermissionDeniedException):
            requires_extension_ownership(connection, handler)


# ---------------------------------------------------------------------------
# requires_phone_number_access
# ---------------------------------------------------------------------------


class TestRequiresPhoneNumberAccess:
    """Tests for the requires_phone_number_access guard."""

    def test_superuser_bypasses_guard(self) -> None:
        """Superuser should pass without checking roles."""
        connection = _make_connection(is_superuser=True)
        handler = _make_handler()

        # Should not raise
        requires_phone_number_access(connection, handler)

    def test_system_role_bypasses_guard(self) -> None:
        """User with SUPERUSER_ACCESS_ROLE should pass."""
        role = _make_role(constants.SUPERUSER_ACCESS_ROLE)
        connection = _make_connection(is_superuser=False, roles=[role])
        handler = _make_handler()

        # Should not raise
        requires_phone_number_access(connection, handler)

    def test_regular_user_denied(self) -> None:
        """Regular user without superuser or system role should be denied."""
        connection = _make_connection(is_superuser=False)
        handler = _make_handler()

        with pytest.raises(PermissionDeniedException) as exc_info:
            requires_phone_number_access(connection, handler)

        assert "phone number" in str(exc_info.value.detail).lower()

    def test_user_with_non_matching_role_denied(self) -> None:
        """User with roles that do not match SUPERUSER_ACCESS_ROLE should be denied."""
        role = _make_role("member")
        connection = _make_connection(is_superuser=False, roles=[role])
        handler = _make_handler()

        with pytest.raises(PermissionDeniedException):
            requires_phone_number_access(connection, handler)

    def test_user_with_multiple_roles_one_matching(self) -> None:
        """User with multiple roles where one matches should pass."""
        roles = [
            _make_role("member"),
            _make_role("admin"),
            _make_role(constants.SUPERUSER_ACCESS_ROLE),
        ]
        connection = _make_connection(is_superuser=False, roles=roles)
        handler = _make_handler()

        # Should not raise
        requires_phone_number_access(connection, handler)

    def test_user_with_empty_roles_denied(self) -> None:
        """User with an empty roles list should be denied."""
        connection = _make_connection(is_superuser=False, roles=[])
        handler = _make_handler()

        with pytest.raises(PermissionDeniedException):
            requires_phone_number_access(connection, handler)

    def test_error_message_differs_from_extension_guard(self) -> None:
        """Verify each guard produces a distinct error message."""
        connection = _make_connection(is_superuser=False)
        handler = _make_handler()

        with pytest.raises(PermissionDeniedException) as ext_exc:
            requires_extension_ownership(connection, handler)

        with pytest.raises(PermissionDeniedException) as phone_exc:
            requires_phone_number_access(connection, handler)

        assert str(ext_exc.value.detail) != str(phone_exc.value.detail)
