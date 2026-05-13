"""Tests for shared guard utilities."""

from __future__ import annotations

from unittest.mock import Mock

import pytest
from litestar.exceptions import PermissionDeniedException

from app.lib import constants
from app.lib.guards import has_superuser_access, require_superuser_access


def _make_role(role_name: str) -> Mock:
    role = Mock()
    role.role_name = role_name
    return role


def _make_connection(*, is_superuser: bool = False, roles: list[Mock] | None = None) -> Mock:
    connection = Mock()
    connection.user.is_superuser = is_superuser
    connection.user.roles = roles if roles is not None else []
    return connection


class TestHasSuperuserAccess:
    def test_superuser_flag(self) -> None:
        assert has_superuser_access(_make_connection(is_superuser=True)) is True

    def test_superuser_role(self) -> None:
        role = _make_role(constants.SUPERUSER_ACCESS_ROLE)
        assert has_superuser_access(_make_connection(roles=[role])) is True

    def test_no_access(self) -> None:
        assert has_superuser_access(_make_connection()) is False

    def test_wrong_role(self) -> None:
        role = _make_role("viewer")
        assert has_superuser_access(_make_connection(roles=[role])) is False

    def test_multiple_roles_one_matching(self) -> None:
        roles = [_make_role("viewer"), _make_role(constants.SUPERUSER_ACCESS_ROLE)]
        assert has_superuser_access(_make_connection(roles=roles)) is True


class TestRequireSuperuserAccess:
    def test_passes_for_superuser(self) -> None:
        require_superuser_access(_make_connection(is_superuser=True))

    def test_raises_for_regular_user(self) -> None:
        with pytest.raises(PermissionDeniedException):
            require_superuser_access(_make_connection())

    def test_custom_detail(self) -> None:
        with pytest.raises(PermissionDeniedException, match="Custom msg"):
            require_superuser_access(_make_connection(), detail="Custom msg")
