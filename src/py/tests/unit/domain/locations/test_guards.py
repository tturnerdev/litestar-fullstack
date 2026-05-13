"""Tests for location domain guards."""

from __future__ import annotations

from unittest.mock import Mock
from uuid import uuid4

import pytest
from litestar.exceptions import PermissionDeniedException

from app.domain.locations.guards import requires_location_team_membership
from app.lib import constants


def _make_role(role_name: str) -> Mock:
    role = Mock()
    role.role_name = role_name
    return role


def _make_team_membership(team_id: str) -> Mock:
    membership = Mock()
    membership.team.id = team_id
    return membership


def _make_connection(
    *,
    is_superuser: bool = False,
    roles: list[Mock] | None = None,
    teams: list[Mock] | None = None,
    path_params: dict | None = None,
) -> Mock:
    connection = Mock()
    connection.user.is_superuser = is_superuser
    connection.user.roles = roles if roles is not None else []
    connection.user.teams = teams if teams is not None else []
    connection.path_params = path_params if path_params is not None else {}
    return connection


class TestRequiresLocationTeamMembership:
    def test_superuser_passes(self) -> None:
        team_id = str(uuid4())
        connection = _make_connection(
            is_superuser=True,
            path_params={"team_id": team_id},
        )
        requires_location_team_membership(connection, Mock())

    def test_superuser_role_passes(self) -> None:
        team_id = str(uuid4())
        connection = _make_connection(
            roles=[_make_role(constants.SUPERUSER_ACCESS_ROLE)],
            path_params={"team_id": team_id},
        )
        requires_location_team_membership(connection, Mock())

    def test_team_member_passes(self) -> None:
        team_id = str(uuid4())
        connection = _make_connection(
            teams=[_make_team_membership(team_id)],
            path_params={"team_id": team_id},
        )
        requires_location_team_membership(connection, Mock())

    def test_non_member_denied(self) -> None:
        connection = _make_connection(
            path_params={"team_id": str(uuid4())},
        )
        with pytest.raises(PermissionDeniedException, match="member of this team"):
            requires_location_team_membership(connection, Mock())

    def test_wrong_team_denied(self) -> None:
        connection = _make_connection(
            teams=[_make_team_membership(str(uuid4()))],
            path_params={"team_id": str(uuid4())},
        )
        with pytest.raises(PermissionDeniedException):
            requires_location_team_membership(connection, Mock())
