"""Tests for fax domain guards."""

from __future__ import annotations

from unittest.mock import Mock

from app.domain.fax.guards import requires_fax_message_access, requires_fax_number_access
from app.lib import constants


def _make_role(role_name: str) -> Mock:
    role = Mock()
    role.role_name = role_name
    return role


def _make_connection(
    *,
    is_superuser: bool = False,
    roles: list[Mock] | None = None,
) -> Mock:
    connection = Mock()
    connection.user.is_superuser = is_superuser
    connection.user.roles = roles if roles is not None else []
    return connection


class TestRequiresFaxNumberAccess:
    def test_superuser_passes(self) -> None:
        connection = _make_connection(is_superuser=True)
        requires_fax_number_access(connection, Mock())

    def test_superuser_role_passes(self) -> None:
        connection = _make_connection(roles=[_make_role(constants.SUPERUSER_ACCESS_ROLE)])
        requires_fax_number_access(connection, Mock())

    def test_non_superuser_passes(self) -> None:
        connection = _make_connection()
        requires_fax_number_access(connection, Mock())


class TestRequiresFaxMessageAccess:
    def test_superuser_passes(self) -> None:
        connection = _make_connection(is_superuser=True)
        requires_fax_message_access(connection, Mock())

    def test_superuser_role_passes(self) -> None:
        connection = _make_connection(roles=[_make_role(constants.SUPERUSER_ACCESS_ROLE)])
        requires_fax_message_access(connection, Mock())

    def test_non_superuser_passes(self) -> None:
        connection = _make_connection()
        requires_fax_message_access(connection, Mock())
