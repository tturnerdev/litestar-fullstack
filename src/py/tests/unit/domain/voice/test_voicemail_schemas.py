"""Tests for voice voicemail schema validation."""

from __future__ import annotations

from uuid import uuid4

import msgspec
import pytest

from app.domain.voice.schemas._voicemail import VoicemailSettingsUpdate
from app.lib.validation import ValidationError


class TestVoicemailSettingsUpdate:
    def test_valid_email(self) -> None:
        u = VoicemailSettingsUpdate(email_address="vm@example.com")
        assert u.email_address == "vm@example.com"

    def test_invalid_email(self) -> None:
        with pytest.raises(ValidationError):
            VoicemailSettingsUpdate(email_address="bad")

    def test_normalizes_email(self) -> None:
        u = VoicemailSettingsUpdate(email_address="VM@Example.COM")
        assert u.email_address == "vm@example.com"

    def test_skips_email_when_unset(self) -> None:
        u = VoicemailSettingsUpdate(is_enabled=False)
        assert u.email_address is msgspec.UNSET
