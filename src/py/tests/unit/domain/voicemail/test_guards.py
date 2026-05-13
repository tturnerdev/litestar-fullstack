"""Tests for voicemail domain guards."""

from __future__ import annotations

from unittest.mock import Mock

from app.domain.voicemail.guards import (
    _has_system_access,
    requires_voicemail_access,
    requires_voicemail_message_access,
)
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


class TestHasSystemAccess:
    def test_superuser(self) -> None:
        user = Mock()
        user.is_superuser = True
        user.roles = []
        assert _has_system_access(user) is True

    def test_superuser_role(self) -> None:
        user = Mock()
        user.is_superuser = False
        user.roles = [_make_role(constants.SUPERUSER_ACCESS_ROLE)]
        assert _has_system_access(user) is True

    def test_regular_user(self) -> None:
        user = Mock()
        user.is_superuser = False
        user.roles = [_make_role("User")]
        assert _has_system_access(user) is False

    def test_no_roles(self) -> None:
        user = Mock()
        user.is_superuser = False
        user.roles = []
        assert _has_system_access(user) is False


class TestRequiresVoicemailAccess:
    def test_superuser_passes(self) -> None:
        connection = _make_connection(is_superuser=True)
        requires_voicemail_access(connection, Mock())

    def test_superuser_role_passes(self) -> None:
        connection = _make_connection(roles=[_make_role(constants.SUPERUSER_ACCESS_ROLE)])
        requires_voicemail_access(connection, Mock())

    def test_non_superuser_passes(self) -> None:
        connection = _make_connection()
        requires_voicemail_access(connection, Mock())


class TestRequiresVoicemailMessageAccess:
    def test_superuser_passes(self) -> None:
        connection = _make_connection(is_superuser=True)
        requires_voicemail_message_access(connection, Mock())

    def test_superuser_role_passes(self) -> None:
        connection = _make_connection(roles=[_make_role(constants.SUPERUSER_ACCESS_ROLE)])
        requires_voicemail_message_access(connection, Mock())

    def test_non_superuser_passes(self) -> None:
        connection = _make_connection()
        requires_voicemail_message_access(connection, Mock())
