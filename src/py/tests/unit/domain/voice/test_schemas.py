"""Unit tests for voice domain schemas.

Tests schema construction, default values, and UNSET fields for:
- DnD (DndSettings, DndSettingsUpdate, DndToggleResponse)
- Extension (Extension, ExtensionCreate, ExtensionUpdate)
- ForwardingRule (ForwardingRule, ForwardingRuleCreate, ForwardingRuleUpdate)
- PhoneNumber (PhoneNumber, PhoneNumberCreate, PhoneNumberUpdate)
- Voicemail (VoicemailSettings, VoicemailSettingsUpdate, VoicemailMessage, VoicemailMessageUpdate)
"""

from __future__ import annotations

from datetime import datetime, time
from uuid import uuid4

import msgspec
import pytest

from app.db.models._voice_enums import (
    DndMode,
    ForwardingDestinationType,
    ForwardingRuleType,
    GreetingType,
    PhoneNumberType,
)
from app.domain.voice.schemas import (
    DndSettings,
    DndSettingsUpdate,
    DndToggleResponse,
    Extension,
    ExtensionCreate,
    ExtensionUpdate,
    ForwardingRule,
    ForwardingRuleCreate,
    ForwardingRuleUpdate,
    PhoneNumber,
    PhoneNumberCreate,
    PhoneNumberUpdate,
    VoicemailMessage,
    VoicemailMessageUpdate,
    VoicemailSettings,
    VoicemailSettingsUpdate,
)

pytestmark = [pytest.mark.unit]


# ---------------------------------------------------------------------------
# DnD schemas
# ---------------------------------------------------------------------------


class TestDndSettings:
    """Tests for DndSettings response schema."""

    def test_defaults(self) -> None:
        """Verify DndSettings applies correct defaults."""
        uid = uuid4()
        ext_id = uuid4()

        settings = DndSettings(id=uid, extension_id=ext_id)

        assert settings.id == uid
        assert settings.extension_id == ext_id
        assert settings.is_enabled is False
        assert settings.mode == DndMode.OFF
        assert settings.schedule_start is None
        assert settings.schedule_end is None
        assert settings.schedule_days is None
        assert settings.allow_list is None

    def test_all_fields(self) -> None:
        """Verify DndSettings preserves all supplied values."""
        start = time(9, 0)
        end = time(17, 0)
        days = [1, 2, 3, 4, 5]
        allow = ["+15551234567"]

        settings = DndSettings(
            id=uuid4(),
            extension_id=uuid4(),
            is_enabled=True,
            mode=DndMode.SCHEDULED,
            schedule_start=start,
            schedule_end=end,
            schedule_days=days,
            allow_list=allow,
        )

        assert settings.is_enabled is True
        assert settings.mode == DndMode.SCHEDULED
        assert settings.schedule_start == start
        assert settings.schedule_end == end
        assert settings.schedule_days == days
        assert settings.allow_list == allow

    def test_always_mode(self) -> None:
        """Verify DndSettings accepts ALWAYS mode."""
        settings = DndSettings(
            id=uuid4(),
            extension_id=uuid4(),
            is_enabled=True,
            mode=DndMode.ALWAYS,
        )

        assert settings.mode == DndMode.ALWAYS


class TestDndSettingsUpdate:
    """Tests for DndSettingsUpdate schema."""

    def test_all_unset_by_default(self) -> None:
        """Verify all fields default to UNSET."""
        update = DndSettingsUpdate()

        assert update.is_enabled is msgspec.UNSET
        assert update.mode is msgspec.UNSET
        assert update.schedule_start is msgspec.UNSET
        assert update.schedule_end is msgspec.UNSET
        assert update.schedule_days is msgspec.UNSET
        assert update.allow_list is msgspec.UNSET

    def test_partial_update(self) -> None:
        """Verify partial fields can be set while others remain UNSET."""
        update = DndSettingsUpdate(is_enabled=True, mode=DndMode.ALWAYS)

        assert update.is_enabled is True
        assert update.mode == DndMode.ALWAYS
        assert update.schedule_start is msgspec.UNSET
        assert update.schedule_end is msgspec.UNSET

    def test_nullable_fields_accept_none(self) -> None:
        """Verify nullable UNSET fields accept explicit None to clear values."""
        update = DndSettingsUpdate(
            schedule_start=None,
            schedule_end=None,
            schedule_days=None,
            allow_list=None,
        )

        assert update.schedule_start is None
        assert update.schedule_end is None
        assert update.schedule_days is None
        assert update.allow_list is None


class TestDndToggleResponse:
    """Tests for DndToggleResponse schema."""

    def test_enabled(self) -> None:
        """Verify DndToggleResponse with enabled=True."""
        resp = DndToggleResponse(is_enabled=True)
        assert resp.is_enabled is True

    def test_disabled(self) -> None:
        """Verify DndToggleResponse with enabled=False."""
        resp = DndToggleResponse(is_enabled=False)
        assert resp.is_enabled is False


# ---------------------------------------------------------------------------
# Extension schemas
# ---------------------------------------------------------------------------


class TestExtension:
    """Tests for Extension response schema."""

    def test_defaults(self) -> None:
        """Verify Extension applies correct defaults."""
        uid = uuid4()
        user_id = uuid4()

        ext = Extension(id=uid, user_id=user_id, extension_number="101")

        assert ext.id == uid
        assert ext.user_id == user_id
        assert ext.extension_number == "101"
        assert ext.phone_number_id is None
        assert ext.display_name == ""
        assert ext.is_active is True

    def test_all_fields(self) -> None:
        """Verify Extension preserves all supplied values."""
        phone_id = uuid4()

        ext = Extension(
            id=uuid4(),
            user_id=uuid4(),
            extension_number="200",
            phone_number_id=phone_id,
            display_name="Front Desk",
            is_active=False,
        )

        assert ext.extension_number == "200"
        assert ext.phone_number_id == phone_id
        assert ext.display_name == "Front Desk"
        assert ext.is_active is False


class TestExtensionCreate:
    """Tests for ExtensionCreate schema."""

    def test_required_only(self) -> None:
        """Verify ExtensionCreate with only required fields."""
        create = ExtensionCreate(extension_number="300")

        assert create.extension_number == "300"
        assert create.display_name == ""
        assert create.phone_number_id is None
        assert create.is_active is True

    def test_all_fields(self) -> None:
        """Verify ExtensionCreate with all fields provided."""
        phone_id = uuid4()

        create = ExtensionCreate(
            extension_number="301",
            display_name="Conference Room",
            phone_number_id=phone_id,
            is_active=False,
        )

        assert create.extension_number == "301"
        assert create.display_name == "Conference Room"
        assert create.phone_number_id == phone_id
        assert create.is_active is False


class TestExtensionUpdate:
    """Tests for ExtensionUpdate schema."""

    def test_all_unset_by_default(self) -> None:
        """Verify all fields default to UNSET."""
        update = ExtensionUpdate()

        assert update.display_name is msgspec.UNSET
        assert update.phone_number_id is msgspec.UNSET
        assert update.is_active is msgspec.UNSET

    def test_partial_update(self) -> None:
        """Verify partial fields can be set while others remain UNSET."""
        update = ExtensionUpdate(display_name="Updated Name")

        assert update.display_name == "Updated Name"
        assert update.phone_number_id is msgspec.UNSET
        assert update.is_active is msgspec.UNSET

    def test_nullable_field_accepts_none(self) -> None:
        """Verify phone_number_id can be explicitly set to None."""
        update = ExtensionUpdate(phone_number_id=None)

        assert update.phone_number_id is None


# ---------------------------------------------------------------------------
# ForwardingRule schemas
# ---------------------------------------------------------------------------


class TestForwardingRule:
    """Tests for ForwardingRule response schema."""

    def test_defaults(self) -> None:
        """Verify ForwardingRule applies correct defaults."""
        uid = uuid4()
        ext_id = uuid4()

        rule = ForwardingRule(
            id=uid,
            extension_id=ext_id,
            rule_type=ForwardingRuleType.ALWAYS,
            destination_type=ForwardingDestinationType.EXTENSION,
            destination_value="102",
        )

        assert rule.id == uid
        assert rule.extension_id == ext_id
        assert rule.rule_type == ForwardingRuleType.ALWAYS
        assert rule.destination_type == ForwardingDestinationType.EXTENSION
        assert rule.destination_value == "102"
        assert rule.ring_timeout_seconds is None
        assert rule.is_active is True
        assert rule.priority == 0

    def test_all_fields(self) -> None:
        """Verify ForwardingRule preserves all supplied values."""
        rule = ForwardingRule(
            id=uuid4(),
            extension_id=uuid4(),
            rule_type=ForwardingRuleType.NO_ANSWER,
            destination_type=ForwardingDestinationType.VOICEMAIL,
            destination_value="vm-101",
            ring_timeout_seconds=30,
            is_active=False,
            priority=5,
        )

        assert rule.rule_type == ForwardingRuleType.NO_ANSWER
        assert rule.destination_type == ForwardingDestinationType.VOICEMAIL
        assert rule.ring_timeout_seconds == 30
        assert rule.is_active is False
        assert rule.priority == 5

    def test_all_rule_types(self) -> None:
        """Verify all ForwardingRuleType enum values are accepted."""
        for rule_type in ForwardingRuleType:
            rule = ForwardingRule(
                id=uuid4(),
                extension_id=uuid4(),
                rule_type=rule_type,
                destination_type=ForwardingDestinationType.EXTERNAL,
                destination_value="+15551234567",
            )
            assert rule.rule_type == rule_type

    def test_all_destination_types(self) -> None:
        """Verify all ForwardingDestinationType enum values are accepted."""
        for dest_type in ForwardingDestinationType:
            rule = ForwardingRule(
                id=uuid4(),
                extension_id=uuid4(),
                rule_type=ForwardingRuleType.BUSY,
                destination_type=dest_type,
                destination_value="dest-value",
            )
            assert rule.destination_type == dest_type


class TestForwardingRuleCreate:
    """Tests for ForwardingRuleCreate schema."""

    def test_required_only(self) -> None:
        """Verify ForwardingRuleCreate with only required fields."""
        create = ForwardingRuleCreate(
            rule_type=ForwardingRuleType.ALWAYS,
            destination_type=ForwardingDestinationType.EXTENSION,
            destination_value="102",
        )

        assert create.rule_type == ForwardingRuleType.ALWAYS
        assert create.destination_type == ForwardingDestinationType.EXTENSION
        assert create.destination_value == "102"
        assert create.ring_timeout_seconds is None
        assert create.is_active is True
        assert create.priority == 0

    def test_all_fields(self) -> None:
        """Verify ForwardingRuleCreate with all fields provided."""
        create = ForwardingRuleCreate(
            rule_type=ForwardingRuleType.UNREACHABLE,
            destination_type=ForwardingDestinationType.EXTERNAL,
            destination_value="+15559876543",
            ring_timeout_seconds=45,
            is_active=False,
            priority=10,
        )

        assert create.ring_timeout_seconds == 45
        assert create.is_active is False
        assert create.priority == 10


class TestForwardingRuleUpdate:
    """Tests for ForwardingRuleUpdate schema."""

    def test_all_unset_by_default(self) -> None:
        """Verify all fields default to UNSET."""
        update = ForwardingRuleUpdate()

        assert update.rule_type is msgspec.UNSET
        assert update.destination_type is msgspec.UNSET
        assert update.destination_value is msgspec.UNSET
        assert update.ring_timeout_seconds is msgspec.UNSET
        assert update.is_active is msgspec.UNSET
        assert update.priority is msgspec.UNSET

    def test_partial_update(self) -> None:
        """Verify partial fields can be set while others remain UNSET."""
        update = ForwardingRuleUpdate(
            destination_value="+15559999999",
            priority=3,
        )

        assert update.destination_value == "+15559999999"
        assert update.priority == 3
        assert update.rule_type is msgspec.UNSET
        assert update.is_active is msgspec.UNSET

    def test_nullable_field_accepts_none(self) -> None:
        """Verify ring_timeout_seconds can be explicitly set to None."""
        update = ForwardingRuleUpdate(ring_timeout_seconds=None)

        assert update.ring_timeout_seconds is None


# ---------------------------------------------------------------------------
# PhoneNumber schemas
# ---------------------------------------------------------------------------


class TestPhoneNumber:
    """Tests for PhoneNumber response schema."""

    def test_defaults(self) -> None:
        """Verify PhoneNumber applies correct defaults."""
        uid = uuid4()
        user_id = uuid4()

        phone = PhoneNumber(id=uid, user_id=user_id, number="+15551234567")

        assert phone.id == uid
        assert phone.user_id == user_id
        assert phone.number == "+15551234567"
        assert phone.label is None
        assert phone.number_type == PhoneNumberType.LOCAL
        assert phone.caller_id_name is None
        assert phone.is_active is True
        assert phone.team_id is None

    def test_all_fields(self) -> None:
        """Verify PhoneNumber preserves all supplied values."""
        team_id = uuid4()

        phone = PhoneNumber(
            id=uuid4(),
            user_id=uuid4(),
            number="+18001234567",
            label="Main Line",
            number_type=PhoneNumberType.TOLL_FREE,
            caller_id_name="Acme Corp",
            is_active=False,
            team_id=team_id,
        )

        assert phone.number == "+18001234567"
        assert phone.label == "Main Line"
        assert phone.number_type == PhoneNumberType.TOLL_FREE
        assert phone.caller_id_name == "Acme Corp"
        assert phone.is_active is False
        assert phone.team_id == team_id

    def test_all_number_types(self) -> None:
        """Verify all PhoneNumberType enum values are accepted."""
        for num_type in PhoneNumberType:
            phone = PhoneNumber(
                id=uuid4(),
                user_id=uuid4(),
                number="+15550000000",
                number_type=num_type,
            )
            assert phone.number_type == num_type


class TestPhoneNumberCreate:
    """Tests for PhoneNumberCreate schema."""

    def test_required_only(self) -> None:
        """Verify PhoneNumberCreate with only required fields."""
        create = PhoneNumberCreate(number="+15551234567")

        assert create.number == "+15551234567"
        assert create.label is None
        assert create.number_type == PhoneNumberType.LOCAL
        assert create.caller_id_name is None
        assert create.is_active is True
        assert create.team_id is None

    def test_all_fields(self) -> None:
        """Verify PhoneNumberCreate with all fields provided."""
        team_id = uuid4()

        create = PhoneNumberCreate(
            number="+442071234567",
            label="UK Office",
            number_type=PhoneNumberType.INTERNATIONAL,
            caller_id_name="UK Branch",
            is_active=True,
            team_id=team_id,
        )

        assert create.number == "+442071234567"
        assert create.label == "UK Office"
        assert create.number_type == PhoneNumberType.INTERNATIONAL
        assert create.caller_id_name == "UK Branch"
        assert create.team_id == team_id


class TestPhoneNumberUpdate:
    """Tests for PhoneNumberUpdate schema."""

    def test_all_unset_by_default(self) -> None:
        """Verify all fields default to UNSET."""
        update = PhoneNumberUpdate()

        assert update.label is msgspec.UNSET
        assert update.caller_id_name is msgspec.UNSET
        assert update.is_active is msgspec.UNSET

    def test_partial_update(self) -> None:
        """Verify partial fields can be set while others remain UNSET."""
        update = PhoneNumberUpdate(label="Updated Label")

        assert update.label == "Updated Label"
        assert update.caller_id_name is msgspec.UNSET
        assert update.is_active is msgspec.UNSET

    def test_nullable_fields_accept_none(self) -> None:
        """Verify nullable fields accept explicit None."""
        update = PhoneNumberUpdate(label=None, caller_id_name=None)

        assert update.label is None
        assert update.caller_id_name is None


# ---------------------------------------------------------------------------
# Voicemail schemas
# ---------------------------------------------------------------------------


class TestVoicemailSettings:
    """Tests for VoicemailSettings response schema."""

    def test_defaults(self) -> None:
        """Verify VoicemailSettings applies correct defaults."""
        uid = uuid4()
        ext_id = uuid4()

        settings = VoicemailSettings(id=uid, extension_id=ext_id)

        assert settings.id == uid
        assert settings.extension_id == ext_id
        assert settings.is_enabled is True
        assert settings.greeting_type == GreetingType.DEFAULT
        assert settings.greeting_file_path is None
        assert settings.max_message_length_seconds == 120
        assert settings.email_notification is True
        assert settings.email_attach_audio is False
        assert settings.transcription_enabled is False
        assert settings.auto_delete_days is None

    def test_all_fields(self) -> None:
        """Verify VoicemailSettings preserves all supplied values."""
        settings = VoicemailSettings(
            id=uuid4(),
            extension_id=uuid4(),
            is_enabled=False,
            greeting_type=GreetingType.CUSTOM,
            greeting_file_path="/audio/greet.wav",
            max_message_length_seconds=300,
            email_notification=False,
            email_attach_audio=True,
            transcription_enabled=True,
            auto_delete_days=30,
        )

        assert settings.is_enabled is False
        assert settings.greeting_type == GreetingType.CUSTOM
        assert settings.greeting_file_path == "/audio/greet.wav"
        assert settings.max_message_length_seconds == 300
        assert settings.email_notification is False
        assert settings.email_attach_audio is True
        assert settings.transcription_enabled is True
        assert settings.auto_delete_days == 30

    def test_all_greeting_types(self) -> None:
        """Verify all GreetingType enum values are accepted."""
        for greeting in GreetingType:
            settings = VoicemailSettings(
                id=uuid4(),
                extension_id=uuid4(),
                greeting_type=greeting,
            )
            assert settings.greeting_type == greeting


class TestVoicemailSettingsUpdate:
    """Tests for VoicemailSettingsUpdate schema."""

    def test_all_unset_by_default(self) -> None:
        """Verify all fields default to UNSET."""
        update = VoicemailSettingsUpdate()

        assert update.is_enabled is msgspec.UNSET
        assert update.pin is msgspec.UNSET
        assert update.greeting_type is msgspec.UNSET
        assert update.max_message_length_seconds is msgspec.UNSET
        assert update.email_notification is msgspec.UNSET
        assert update.email_attach_audio is msgspec.UNSET
        assert update.transcription_enabled is msgspec.UNSET
        assert update.auto_delete_days is msgspec.UNSET

    def test_partial_update(self) -> None:
        """Verify partial fields can be set while others remain UNSET."""
        update = VoicemailSettingsUpdate(
            is_enabled=False,
            pin="1234",
            greeting_type=GreetingType.NAME_ONLY,
        )

        assert update.is_enabled is False
        assert update.pin == "1234"
        assert update.greeting_type == GreetingType.NAME_ONLY
        assert update.max_message_length_seconds is msgspec.UNSET
        assert update.email_notification is msgspec.UNSET

    def test_nullable_fields_accept_none(self) -> None:
        """Verify nullable fields accept explicit None to clear values."""
        update = VoicemailSettingsUpdate(pin=None, auto_delete_days=None)

        assert update.pin is None
        assert update.auto_delete_days is None


class TestVoicemailMessage:
    """Tests for VoicemailMessage response schema."""

    def test_defaults(self) -> None:
        """Verify VoicemailMessage applies correct defaults."""
        uid = uuid4()
        box_id = uuid4()

        msg = VoicemailMessage(
            id=uid,
            voicemail_box_id=box_id,
            caller_number="+15551234567",
        )

        assert msg.id == uid
        assert msg.voicemail_box_id == box_id
        assert msg.caller_number == "+15551234567"
        assert msg.caller_name is None
        assert msg.duration_seconds == 0
        assert msg.audio_file_path == ""
        assert msg.transcription is None
        assert msg.is_read is False
        assert msg.is_urgent is False
        assert msg.received_at is None

    def test_all_fields(self) -> None:
        """Verify VoicemailMessage preserves all supplied values."""
        now = datetime(2025, 1, 15, 10, 30, 0)

        msg = VoicemailMessage(
            id=uuid4(),
            voicemail_box_id=uuid4(),
            caller_number="+15559876543",
            caller_name="Jane Doe",
            duration_seconds=45,
            audio_file_path="/recordings/msg-001.wav",
            transcription="Hello, this is Jane...",
            is_read=True,
            is_urgent=True,
            received_at=now,
        )

        assert msg.caller_name == "Jane Doe"
        assert msg.duration_seconds == 45
        assert msg.audio_file_path == "/recordings/msg-001.wav"
        assert msg.transcription == "Hello, this is Jane..."
        assert msg.is_read is True
        assert msg.is_urgent is True
        assert msg.received_at == now


class TestVoicemailMessageUpdate:
    """Tests for VoicemailMessageUpdate schema."""

    def test_unset_by_default(self) -> None:
        """Verify is_read defaults to UNSET."""
        update = VoicemailMessageUpdate()

        assert update.is_read is msgspec.UNSET

    def test_mark_as_read(self) -> None:
        """Verify is_read can be set to True."""
        update = VoicemailMessageUpdate(is_read=True)

        assert update.is_read is True

    def test_mark_as_unread(self) -> None:
        """Verify is_read can be set to False."""
        update = VoicemailMessageUpdate(is_read=False)

        assert update.is_read is False
