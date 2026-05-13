"""Tests for connection domain schema validation."""

from __future__ import annotations

import msgspec
import pytest

from app.domain.connections.schemas._connection import ConnectionCreate, ConnectionUpdate


class TestConnectionCreate:
    def test_valid(self) -> None:
        c = ConnectionCreate(
            name="PBX Link",
            connection_type="pbx",
            provider="freepbx",
        )
        assert c.name == "PBX Link"

    def test_invalid_connection_type(self) -> None:
        with pytest.raises(ValueError, match="connection_type must be"):
            ConnectionCreate(
                name="Bad",
                connection_type="invalid_type",
                provider="freepbx",
            )

    def test_invalid_auth_type(self) -> None:
        with pytest.raises(ValueError, match="auth_type must be"):
            ConnectionCreate(
                name="Bad",
                connection_type="pbx",
                provider="freepbx",
                auth_type="magic",
            )


class TestConnectionUpdate:
    def test_valid_type_update(self) -> None:
        u = ConnectionUpdate(connection_type="pbx")
        assert u.connection_type == "pbx"

    def test_invalid_type_update(self) -> None:
        with pytest.raises(ValueError, match="connection_type must be"):
            ConnectionUpdate(connection_type="bad_type")

    def test_invalid_auth_type_update(self) -> None:
        with pytest.raises(ValueError, match="auth_type must be"):
            ConnectionUpdate(auth_type="bad_auth")

    def test_skips_validation_when_unset(self) -> None:
        u = ConnectionUpdate(name="Renamed")
        assert u.connection_type is msgspec.UNSET
        assert u.auth_type is msgspec.UNSET
