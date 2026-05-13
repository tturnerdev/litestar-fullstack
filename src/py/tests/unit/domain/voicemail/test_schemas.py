"""Tests for voicemail domain schema validation."""

from __future__ import annotations

from uuid import uuid4

import msgspec
import pytest

from app.domain.voicemail.schemas._voicemail_box import VoicemailBoxCreate, VoicemailBoxUpdate
from app.lib.validation import ValidationError


class TestVoicemailBoxCreate:
    def test_valid_minimal(self) -> None:
        v = VoicemailBoxCreate(extension_id=uuid4())
        assert v.email_address is None

    def test_valid_with_email(self) -> None:
        v = VoicemailBoxCreate(extension_id=uuid4(), email_address="vm@example.com")
        assert v.email_address == "vm@example.com"

    def test_invalid_email(self) -> None:
        with pytest.raises(ValidationError):
            VoicemailBoxCreate(extension_id=uuid4(), email_address="bad")

    def test_normalizes_email(self) -> None:
        v = VoicemailBoxCreate(extension_id=uuid4(), email_address="VM@Example.COM")
        assert v.email_address == "vm@example.com"


class TestVoicemailBoxUpdate:
    def test_validates_email_when_set(self) -> None:
        u = VoicemailBoxUpdate(email_address="new@example.com")
        assert u.email_address == "new@example.com"

    def test_invalid_email(self) -> None:
        with pytest.raises(ValidationError):
            VoicemailBoxUpdate(email_address="bad")

    def test_skips_validation_when_unset(self) -> None:
        u = VoicemailBoxUpdate(is_enabled=False)
        assert u.email_address is msgspec.UNSET
