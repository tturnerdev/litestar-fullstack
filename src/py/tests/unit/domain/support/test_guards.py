"""Tests for support domain guards."""

from __future__ import annotations

from unittest.mock import Mock

import pytest
from litestar.exceptions import PermissionDeniedException

from app.domain.support.guards import (
    requires_support_agent,
    requires_ticket_access,
    requires_ticket_message_edit,
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


class TestRequiresTicketAccess:
    def test_superuser_passes(self) -> None:
        connection = _make_connection(is_superuser=True)
        requires_ticket_access(connection, Mock())

    def test_superuser_role_passes(self) -> None:
        connection = _make_connection(roles=[_make_role(constants.SUPERUSER_ACCESS_ROLE)])
        requires_ticket_access(connection, Mock())

    def test_non_superuser_passes(self) -> None:
        connection = _make_connection()
        requires_ticket_access(connection, Mock())


class TestRequiresTicketMessageEdit:
    def test_superuser_passes(self) -> None:
        connection = _make_connection(is_superuser=True)
        requires_ticket_message_edit(connection, Mock())

    def test_superuser_role_passes(self) -> None:
        connection = _make_connection(roles=[_make_role(constants.SUPERUSER_ACCESS_ROLE)])
        requires_ticket_message_edit(connection, Mock())

    def test_non_superuser_passes(self) -> None:
        connection = _make_connection()
        requires_ticket_message_edit(connection, Mock())


class TestRequiresSupportAgent:
    def test_superuser_passes(self) -> None:
        connection = _make_connection(is_superuser=True)
        requires_support_agent(connection, Mock())

    def test_superuser_role_passes(self) -> None:
        connection = _make_connection(roles=[_make_role(constants.SUPERUSER_ACCESS_ROLE)])
        requires_support_agent(connection, Mock())

    def test_non_superuser_denied(self) -> None:
        connection = _make_connection()
        with pytest.raises(PermissionDeniedException, match="Insufficient permissions"):
            requires_support_agent(connection, Mock())
