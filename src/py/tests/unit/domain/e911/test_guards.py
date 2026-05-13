"""Tests for E911 domain guards."""

from __future__ import annotations

from unittest.mock import Mock

import pytest
from litestar.exceptions import PermissionDeniedException

from app.domain.e911.guards import requires_team_membership
from app.lib import constants


def _make_role(role_name: str) -> Mock:
    role = Mock()
    role.role_name = role_name
    return role


def _make_connection(
    *,
    is_superuser: bool = False,
    roles: list[Mock] | None = None,
    teams: list[Mock] | None = None,
) -> Mock:
    connection = Mock()
    connection.user.is_superuser = is_superuser
    connection.user.roles = roles if roles is not None else []
    connection.user.teams = teams if teams is not None else []
    return connection


class TestRequiresTeamMembership:
    def test_superuser_passes(self) -> None:
        connection = _make_connection(is_superuser=True)
        requires_team_membership(connection, Mock())

    def test_superuser_role_passes(self) -> None:
        connection = _make_connection(roles=[_make_role(constants.SUPERUSER_ACCESS_ROLE)])
        requires_team_membership(connection, Mock())

    def test_user_with_teams_passes(self) -> None:
        connection = _make_connection(teams=[Mock()])
        requires_team_membership(connection, Mock())

    def test_user_without_teams_denied(self) -> None:
        connection = _make_connection()
        with pytest.raises(PermissionDeniedException, match="team membership"):
            requires_team_membership(connection, Mock())

    def test_non_superuser_no_teams_denied(self) -> None:
        connection = _make_connection(roles=[_make_role("User")])
        with pytest.raises(PermissionDeniedException):
            requires_team_membership(connection, Mock())
