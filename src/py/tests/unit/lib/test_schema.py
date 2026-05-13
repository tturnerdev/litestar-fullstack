"""Tests for app.lib.schema base classes."""

from __future__ import annotations

import msgspec

from app.lib.schema import BaseStruct, CamelizedBaseStruct, Message


class _TestStruct(BaseStruct):
    name: str
    value: int
    optional: str | msgspec.UnsetType = msgspec.UNSET


class _CamelStruct(CamelizedBaseStruct):
    user_name: str
    is_active: bool


class TestBaseStruct:
    def test_to_dict_all_set(self) -> None:
        s = _TestStruct(name="test", value=42, optional="yes")
        d = s.to_dict()
        assert d == {"name": "test", "value": 42, "optional": "yes"}

    def test_to_dict_excludes_unset(self) -> None:
        s = _TestStruct(name="test", value=42)
        d = s.to_dict()
        assert d == {"name": "test", "value": 42}
        assert "optional" not in d


class TestCamelizedBaseStruct:
    def test_camel_rename(self) -> None:
        data = msgspec.json.encode({"userName": "alice", "isActive": True})
        s = msgspec.json.decode(data, type=_CamelStruct)
        assert s.user_name == "alice"
        assert s.is_active is True

    def test_camel_encode(self) -> None:
        s = _CamelStruct(user_name="alice", is_active=True)
        encoded = msgspec.json.decode(msgspec.json.encode(s))
        assert "userName" in encoded
        assert "isActive" in encoded


class TestMessage:
    def test_message_struct(self) -> None:
        m = Message(message="hello")
        assert m.message == "hello"

    def test_message_camelized(self) -> None:
        encoded = msgspec.json.decode(msgspec.json.encode(Message(message="ok")))
        assert encoded["message"] == "ok"
