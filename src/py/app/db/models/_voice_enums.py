from __future__ import annotations

from enum import StrEnum


class PhoneNumberType(StrEnum):
    """Valid phone number types."""

    LOCAL = "local"
    TOLL_FREE = "toll_free"
    INTERNATIONAL = "international"


class GreetingType(StrEnum):
    """Valid voicemail greeting types."""

    DEFAULT = "default"
    CUSTOM = "custom"
    NAME_ONLY = "name_only"


class ForwardingRuleType(StrEnum):
    """Valid forwarding rule types."""

    ALWAYS = "always"
    BUSY = "busy"
    NO_ANSWER = "no_answer"
    UNREACHABLE = "unreachable"


class ForwardingDestinationType(StrEnum):
    """Valid forwarding destination types."""

    EXTENSION = "extension"
    EXTERNAL = "external"
    VOICEMAIL = "voicemail"


class DndMode(StrEnum):
    """Valid DND modes."""

    ALWAYS = "always"
    SCHEDULED = "scheduled"
    OFF = "off"
