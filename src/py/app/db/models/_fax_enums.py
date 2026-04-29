from __future__ import annotations

from enum import StrEnum



class FaxDirection(StrEnum):
    """Valid values for fax message direction."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"


class FaxStatus(StrEnum):
    """Valid values for fax message status."""

    QUEUED = "queued"
    RECEIVED = "received"
    DELIVERED = "delivered"
    FAILED = "failed"
    SENDING = "sending"
    SENT = "sent"
