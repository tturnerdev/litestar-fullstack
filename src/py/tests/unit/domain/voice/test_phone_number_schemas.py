"""Tests for voice phone number schema validation."""

from __future__ import annotations

import pytest

from app.domain.voice.schemas._phone_number import PhoneNumberCreate
from app.lib.validation import ValidationError


class TestPhoneNumberCreate:
    def test_valid(self) -> None:
        p = PhoneNumberCreate(number="+15551234567")
        assert p.number == "+15551234567"

    def test_invalid_number(self) -> None:
        with pytest.raises(ValidationError):
            PhoneNumberCreate(number="abc")

    def test_with_label(self) -> None:
        p = PhoneNumberCreate(number="+15551234567", label="Main Line")
        assert p.label == "Main Line"
