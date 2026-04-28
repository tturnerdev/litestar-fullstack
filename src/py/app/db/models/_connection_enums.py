from __future__ import annotations

from enum import StrEnum


class ConnectionType(StrEnum):
    """Valid connection types."""

    PBX = "pbx"
    HELPDESK = "helpdesk"
    CARRIER = "carrier"
    OTHER = "other"


class ConnectionAuthType(StrEnum):
    """Valid authentication types for connections."""

    API_KEY = "api_key"
    BASIC = "basic"
    OAUTH2 = "oauth2"
    TOKEN = "token"
    NONE = "none"


class ConnectionStatus(StrEnum):
    """Valid connection statuses."""

    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    UNKNOWN = "unknown"
