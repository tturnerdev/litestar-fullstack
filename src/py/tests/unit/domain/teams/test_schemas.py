"""Tests for team domain schema validation."""

from __future__ import annotations

from uuid import uuid4

from app.db.models._team_roles import TeamRoles
from app.domain.teams.schemas._member import TeamMember, TeamMemberModify, TeamMemberUpdate


class TestTeamMember:
    def test_default_role(self) -> None:
        m = TeamMember(id=uuid4(), user_id=uuid4(), email="u@example.com")
        assert m.role == TeamRoles.MEMBER

    def test_explicit_role(self) -> None:
        m = TeamMember(id=uuid4(), user_id=uuid4(), email="u@example.com", role=TeamRoles.ADMIN)
        assert m.role == TeamRoles.ADMIN

    def test_none_role_defaults(self) -> None:
        m = TeamMember(id=uuid4(), user_id=uuid4(), email="u@example.com", role=None)
        assert m.role == TeamRoles.MEMBER

    def test_name_optional(self) -> None:
        m = TeamMember(id=uuid4(), user_id=uuid4(), email="u@example.com", name="John")
        assert m.name == "John"

    def test_is_owner_default(self) -> None:
        m = TeamMember(id=uuid4(), user_id=uuid4(), email="u@example.com")
        assert m.is_owner is False


class TestTeamMemberModify:
    def test_valid(self) -> None:
        m = TeamMemberModify(user_name="johndoe")
        assert m.user_name == "johndoe"


class TestTeamMemberUpdate:
    def test_valid(self) -> None:
        m = TeamMemberUpdate(role=TeamRoles.ADMIN)
        assert m.role == TeamRoles.ADMIN
