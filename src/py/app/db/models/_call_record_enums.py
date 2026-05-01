from __future__ import annotations

from enum import StrEnum


class CallDirection(StrEnum):
    """Valid call direction values."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"


class CallDisposition(StrEnum):
    """Valid call disposition values."""

    ANSWERED = "answered"
    NO_ANSWER = "no_answer"
    BUSY = "busy"
    FAILED = "failed"
    VOICEMAIL = "voicemail"
