from __future__ import annotations

from enum import StrEnum


class OverrideMode(StrEnum):
    """Valid time condition override modes."""

    NONE = "none"
    FORCE_MATCH = "force_match"
    FORCE_NO_MATCH = "force_no_match"


class IvrGreetingType(StrEnum):
    """Valid IVR menu greeting types."""

    TTS = "tts"
    UPLOAD = "upload"
    NONE = "none"


class QueueStrategy(StrEnum):
    """Valid call queue ring strategies."""

    RING_ALL = "ring_all"
    ROUND_ROBIN = "round_robin"
    LONGEST_IDLE = "longest_idle"
    LINEAR_HUNT = "linear_hunt"
    RANDOM = "random"


class RingGroupStrategy(StrEnum):
    """Valid ring group ring strategies."""

    RING_ALL = "ring_all"
    ROUND_ROBIN = "round_robin"
    LINEAR_HUNT = "linear_hunt"
