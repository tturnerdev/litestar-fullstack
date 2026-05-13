"""Tests for E911 schema validation."""

from __future__ import annotations

from uuid import uuid4

import msgspec
import pytest

from app.domain.e911.schemas._e911_registration import E911RegistrationCreate, E911RegistrationUpdate


class TestE911RegistrationCreate:
    def test_valid(self) -> None:
        r = E911RegistrationCreate(
            team_id=uuid4(),
            address_line_1="123 Main St",
            city="Springfield",
            state="IL",
            postal_code="62701",
        )
        assert r.state == "IL"

    def test_valid_zip_plus_4(self) -> None:
        r = E911RegistrationCreate(
            team_id=uuid4(),
            address_line_1="123 Main St",
            city="Springfield",
            state="IL",
            postal_code="62701-1234",
        )
        assert r.postal_code == "62701-1234"

    def test_invalid_state_lowercase(self) -> None:
        with pytest.raises(ValueError, match="2 uppercase letters"):
            E911RegistrationCreate(
                team_id=uuid4(),
                address_line_1="123 Main St",
                city="Springfield",
                state="il",
                postal_code="62701",
            )

    def test_invalid_state_too_long(self) -> None:
        with pytest.raises(ValueError, match="2 uppercase letters"):
            E911RegistrationCreate(
                team_id=uuid4(),
                address_line_1="123 Main St",
                city="Springfield",
                state="ILL",
                postal_code="62701",
            )

    def test_invalid_postal_code(self) -> None:
        with pytest.raises(ValueError, match="ZIP"):
            E911RegistrationCreate(
                team_id=uuid4(),
                address_line_1="123 Main St",
                city="Springfield",
                state="IL",
                postal_code="ABC",
            )

    def test_invalid_postal_code_partial(self) -> None:
        with pytest.raises(ValueError, match="ZIP"):
            E911RegistrationCreate(
                team_id=uuid4(),
                address_line_1="123 Main St",
                city="Springfield",
                state="IL",
                postal_code="1234",
            )


class TestE911RegistrationUpdate:
    def test_valid_state_update(self) -> None:
        u = E911RegistrationUpdate(state="TX")
        assert u.state == "TX"

    def test_invalid_state_update(self) -> None:
        with pytest.raises(ValueError, match="2 uppercase letters"):
            E911RegistrationUpdate(state="tx")

    def test_valid_postal_code_update(self) -> None:
        u = E911RegistrationUpdate(postal_code="90210")
        assert u.postal_code == "90210"

    def test_invalid_postal_code_update(self) -> None:
        with pytest.raises(ValueError, match="ZIP"):
            E911RegistrationUpdate(postal_code="bad")

    def test_unset_fields_skip_validation(self) -> None:
        u = E911RegistrationUpdate(city="Dallas")
        assert u.city == "Dallas"
        assert u.state is msgspec.UNSET
        assert u.postal_code is msgspec.UNSET
