"""Tests for teams domain guards."""

from __future__ import annotations

from unittest.mock import Mock
from uuid import uuid4

import pytest
from litestar.exceptions import PermissionDeniedException

from app.db.models._team_roles import TeamRoles
from app.domain.teams.guards import (
    requires_team_admin,
    requires_team_membership,
    requires_team_ownership,
)
from app.lib import constants


def _make_role(role_name: str) -> Mock:
    role = Mock()
    role.role_name = role_name
    return role


def _make_team_membership(team_id: str, *, role: TeamRoles = TeamRoles.MEMBER, is_owner: bool = False) -> Mock:
    membership = Mock()
    membership.team.id = team_id
    membership.team_id = team_id
    membership.role = role
    membership.is_owner = is_owner
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


class TestRequiresTeamMembership:
    def test_superuser_passes(self) -> None:
        team_id = str(uuid4())
        connection = _make_connection(is_superuser=True, path_params={"team_id": team_id})
        requires_team_membership(connection, Mock())

    def test_superuser_role_passes(self) -> None:
        team_id = str(uuid4())
        connection = _make_connection(
            roles=[_make_role(constants.SUPERUSER_ACCESS_ROLE)],
            path_params={"team_id": team_id},
        )
        requires_team_membership(connection, Mock())

    def test_member_passes(self) -> None:
        team_id = str(uuid4())
        connection = _make_connection(
            teams=[_make_team_membership(team_id)],
            path_params={"team_id": team_id},
        )
        requires_team_membership(connection, Mock())

    def test_non_member_denied(self) -> None:
        connection = _make_connection(path_params={"team_id": str(uuid4())})
        with pytest.raises(PermissionDeniedException, match="member of this team"):
            requires_team_membership(connection, Mock())

    def test_wrong_team_denied(self) -> None:
        connection = _make_connection(
            teams=[_make_team_membership(str(uuid4()))],
            path_params={"team_id": str(uuid4())},
        )
        with pytest.raises(PermissionDeniedException):
            requires_team_membership(connection, Mock())


class TestRequiresTeamAdmin:
    def test_superuser_passes(self) -> None:
        team_id = str(uuid4())
        connection = _make_connection(is_superuser=True, path_params={"team_id": team_id})
        requires_team_admin(connection, Mock())

    def test_admin_role_passes(self) -> None:
        team_id = str(uuid4())
        connection = _make_connection(
            teams=[_make_team_membership(team_id, role=TeamRoles.ADMIN)],
            path_params={"team_id": team_id},
        )
        requires_team_admin(connection, Mock())

    def test_member_role_denied(self) -> None:
        team_id = str(uuid4())
        connection = _make_connection(
            teams=[_make_team_membership(team_id, role=TeamRoles.MEMBER)],
            path_params={"team_id": team_id},
        )
        with pytest.raises(PermissionDeniedException, match="Team admin role"):
            requires_team_admin(connection, Mock())

    def test_no_membership_denied(self) -> None:
        connection = _make_connection(path_params={"team_id": str(uuid4())})
        with pytest.raises(PermissionDeniedException):
            requires_team_admin(connection, Mock())


class TestRequiresTeamOwnership:
    def test_superuser_passes(self) -> None:
        team_id = str(uuid4())
        connection = _make_connection(is_superuser=True, path_params={"team_id": team_id})
        requires_team_ownership(connection, Mock())

    def test_owner_passes(self) -> None:
        team_id = str(uuid4())
        connection = _make_connection(
            teams=[_make_team_membership(team_id, is_owner=True)],
            path_params={"team_id": team_id},
        )
        requires_team_ownership(connection, Mock())

    def test_non_owner_member_denied(self) -> None:
        team_id = str(uuid4())
        connection = _make_connection(
            teams=[_make_team_membership(team_id, is_owner=False)],
            path_params={"team_id": team_id},
        )
        with pytest.raises(PermissionDeniedException, match="Team owner role"):
            requires_team_ownership(connection, Mock())

    def test_no_membership_denied(self) -> None:
        connection = _make_connection(path_params={"team_id": str(uuid4())})
        with pytest.raises(PermissionDeniedException):
            requires_team_ownership(connection, Mock())
