"""Tests for app.lib.audit utilities."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from sqlalchemy import String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from app.lib.audit import _EXCLUDED_FIELDS, capture_snapshot, compute_diff


class _Base(DeclarativeBase):
    pass


class _FakeModel(_Base):
    __tablename__ = "fake_for_audit_test"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(100))
    slug: Mapped[str] = mapped_column(String(100))
    description: Mapped[str | None] = mapped_column(String(500), default=None)
    hashed_password: Mapped[str | None] = mapped_column(String(200), default=None)


@pytest.fixture()
def fake_model() -> _FakeModel:
    engine = create_engine("sqlite:///:memory:")
    _Base.metadata.create_all(engine)
    with Session(engine) as session:
        obj = _FakeModel(
            id=uuid4(),
            name="Test Item",
            slug="test-item",
            description="A test description",
            hashed_password="should-be-excluded",
        )
        session.add(obj)
        session.flush()
        session.expire(obj)
        session.refresh(obj)
        session.expunge(obj)
    return obj


class TestCaptureSnapshot:
    def test_excludes_default_fields(self, fake_model: _FakeModel) -> None:
        snapshot = capture_snapshot(fake_model)
        assert "id" not in snapshot
        assert "hashed_password" not in snapshot

    def test_includes_normal_fields(self, fake_model: _FakeModel) -> None:
        snapshot = capture_snapshot(fake_model)
        assert snapshot["name"] == "Test Item"
        assert snapshot["slug"] == "test-item"
        assert snapshot["description"] == "A test description"

    def test_serializes_uuid_to_string(self, fake_model: _FakeModel) -> None:
        snapshot = capture_snapshot(fake_model)
        for value in snapshot.values():
            assert not isinstance(value, UUID)

    def test_custom_exclude(self, fake_model: _FakeModel) -> None:
        snapshot = capture_snapshot(fake_model, exclude=frozenset({"slug"}))
        assert "slug" not in snapshot
        assert "name" in snapshot

    def test_none_values_included(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        _Base.metadata.create_all(engine)
        with Session(engine) as session:
            obj = _FakeModel(
                id=uuid4(),
                name="Null Test",
                slug="null-test",
                description=None,
                hashed_password=None,
            )
            session.add(obj)
            session.flush()
            session.refresh(obj)
            session.expunge(obj)
        snapshot = capture_snapshot(obj)
        assert "description" in snapshot
        assert snapshot["description"] is None


class TestComputeDiff:
    def test_both_none(self) -> None:
        assert compute_diff(None, None) == {}

    def test_create_before_none(self) -> None:
        after = {"name": "New", "slug": "new"}
        result = compute_diff(None, after)
        assert result == {"before": None, "after": after}

    def test_delete_after_none(self) -> None:
        before = {"name": "Old", "slug": "old"}
        result = compute_diff(before, None)
        assert result == {"before": before, "after": None}

    def test_no_changes(self) -> None:
        data = {"name": "Same", "slug": "same"}
        assert compute_diff(data, dict(data)) == {}

    def test_changed_fields_only(self) -> None:
        before = {"name": "Old", "slug": "old", "description": "kept"}
        after = {"name": "New", "slug": "new", "description": "kept"}
        result = compute_diff(before, after)
        assert result == {
            "before": {"name": "Old", "slug": "old"},
            "after": {"name": "New", "slug": "new"},
        }

    def test_added_field(self) -> None:
        before = {"name": "Item"}
        after = {"name": "Item", "slug": "item"}
        result = compute_diff(before, after)
        assert result["before"] == {"slug": None}
        assert result["after"] == {"slug": "item"}

    def test_removed_field(self) -> None:
        before = {"name": "Item", "slug": "item"}
        after = {"name": "Item"}
        result = compute_diff(before, after)
        assert result["before"] == {"slug": "item"}
        assert result["after"] == {"slug": None}

    def test_none_to_value(self) -> None:
        before = {"description": None}
        after = {"description": "Now has a value"}
        result = compute_diff(before, after)
        assert result["before"] == {"description": None}
        assert result["after"] == {"description": "Now has a value"}

    def test_value_to_none(self) -> None:
        before = {"description": "Had a value"}
        after = {"description": None}
        result = compute_diff(before, after)
        assert result["before"] == {"description": "Had a value"}
        assert result["after"] == {"description": None}


class TestExcludedFields:
    def test_security_fields_excluded(self) -> None:
        assert "hashed_password" in _EXCLUDED_FIELDS
        assert "totp_secret" in _EXCLUDED_FIELDS
        assert "backup_codes" in _EXCLUDED_FIELDS
        assert "token_hash" in _EXCLUDED_FIELDS

    def test_orm_fields_excluded(self) -> None:
        assert "id" in _EXCLUDED_FIELDS
        assert "sa_orm_sentinel" in _EXCLUDED_FIELDS
        assert "created_at" in _EXCLUDED_FIELDS
        assert "updated_at" in _EXCLUDED_FIELDS
