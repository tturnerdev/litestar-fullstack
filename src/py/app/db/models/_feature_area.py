from __future__ import annotations

from enum import StrEnum


class FeatureArea(StrEnum):
    """Feature areas available for team role permissions.

    Sub-features use a ``PARENT_CHILD`` naming convention.  The guard
    checks the sub-feature first, then falls back to the parent if no
    explicit permission row exists.
    """

    # Voice
    VOICE = "VOICE"
    VOICE_PHONE_NUMBERS = "VOICE_PHONE_NUMBERS"
    VOICE_EXTENSIONS = "VOICE_EXTENSIONS"
    VOICE_VOICEMAIL = "VOICE_VOICEMAIL"
    VOICE_VOICEMAIL_BOXES = "VOICE_VOICEMAIL_BOXES"

    # Fax
    FAX = "FAX"
    FAX_NUMBERS = "FAX_NUMBERS"
    FAX_MESSAGES = "FAX_MESSAGES"
    FAX_EMAIL_ROUTES = "FAX_EMAIL_ROUTES"

    # Call Routing
    CALL_ROUTING = "CALL_ROUTING"
    CALL_ROUTING_QUEUES = "CALL_ROUTING_QUEUES"
    CALL_ROUTING_RING_GROUPS = "CALL_ROUTING_RING_GROUPS"
    CALL_ROUTING_IVR_MENUS = "CALL_ROUTING_IVR_MENUS"
    CALL_ROUTING_TIME_CONDITIONS = "CALL_ROUTING_TIME_CONDITIONS"

    # Support
    SUPPORT = "SUPPORT"
    SUPPORT_TICKETS = "SUPPORT_TICKETS"

    # Standalone (no sub-features)
    CONNECTIONS = "CONNECTIONS"
    DEVICES = "DEVICES"
    E911 = "E911"
    LOCATIONS = "LOCATIONS"
    ORGANIZATION = "ORGANIZATION"
    SCHEDULES = "SCHEDULES"
    TEAMS = "TEAMS"


FEATURE_PARENT_MAP: dict[str, str] = {
    "VOICE_PHONE_NUMBERS": "VOICE",
    "VOICE_EXTENSIONS": "VOICE",
    "VOICE_VOICEMAIL": "VOICE",
    "VOICE_VOICEMAIL_BOXES": "VOICE",
    "FAX_NUMBERS": "FAX",
    "FAX_MESSAGES": "FAX",
    "FAX_EMAIL_ROUTES": "FAX",
    "CALL_ROUTING_QUEUES": "CALL_ROUTING",
    "CALL_ROUTING_RING_GROUPS": "CALL_ROUTING",
    "CALL_ROUTING_IVR_MENUS": "CALL_ROUTING",
    "CALL_ROUTING_TIME_CONDITIONS": "CALL_ROUTING",
    "SUPPORT_TICKETS": "SUPPORT",
}
