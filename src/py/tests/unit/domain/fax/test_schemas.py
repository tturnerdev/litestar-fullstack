"""Tests for fax domain schema validation."""

from __future__ import annotations

import msgspec
import pytest

from app.domain.fax.schemas._fax_email_route import FaxEmailRouteCreate, FaxEmailRouteUpdate
from app.domain.fax.schemas._fax_number import FaxNumberCreate
from app.lib.validation import ValidationError


class TestFaxEmailRouteCreate:
    def test_valid(self) -> None:
        r = FaxEmailRouteCreate(email_address="fax@example.com")
        assert r.email_address == "fax@example.com"

    def test_normalizes_email(self) -> None:
        r = FaxEmailRouteCreate(email_address="FAX@Example.COM")
        assert r.email_address == "fax@example.com"

    def test_invalid_email(self) -> None:
        with pytest.raises(ValidationError):
            FaxEmailRouteCreate(email_address="not-an-email")

    def test_allows_blocked_account_domains(self) -> None:
        r = FaxEmailRouteCreate(email_address="user@10minutemail.com")
        assert r.email_address == "user@10minutemail.com"


class TestFaxEmailRouteUpdate:
    def test_validates_email_when_set(self) -> None:
        u = FaxEmailRouteUpdate(email_address="new@example.com")
        assert u.email_address == "new@example.com"

    def test_invalid_email(self) -> None:
        with pytest.raises(ValidationError):
            FaxEmailRouteUpdate(email_address="bad")

    def test_skips_validation_when_unset(self) -> None:
        u = FaxEmailRouteUpdate(is_active=False)
        assert u.email_address is msgspec.UNSET


class TestFaxNumberCreate:
    def test_valid(self) -> None:
        n = FaxNumberCreate(number="+15551234567")
        assert n.number == "+15551234567"

    def test_invalid_phone(self) -> None:
        with pytest.raises(ValidationError):
            FaxNumberCreate(number="abc")
