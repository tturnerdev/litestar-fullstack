from __future__ import annotations

from enum import StrEnum


class TicketStatus(StrEnum):
    """Valid statuses for support tickets."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    WAITING_ON_CUSTOMER = "waiting_on_customer"
    WAITING_ON_SUPPORT = "waiting_on_support"
    RESOLVED = "resolved"
    CLOSED = "closed"


class TicketPriority(StrEnum):
    """Valid priority levels for support tickets."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


class TicketCategory(StrEnum):
    """Valid categories for support tickets."""

    BILLING = "billing"
    TECHNICAL = "technical"
    ACCOUNT = "account"
    DEVICE = "device"
    VOICE = "voice"
    FAX = "fax"
    GENERAL = "general"
