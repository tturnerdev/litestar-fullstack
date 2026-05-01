"""Admin gateway settings schemas."""

from __future__ import annotations

import msgspec

from app.lib.schema import CamelizedBaseStruct


class AdminGatewaySettings(CamelizedBaseStruct, kw_only=True):
    """Current gateway settings returned to the admin UI."""

    default_timeout: int
    default_cache_ttl: int


class AdminGatewaySettingsUpdate(CamelizedBaseStruct, kw_only=True):
    """Payload for updating gateway settings."""

    default_timeout: int | msgspec.UnsetType = msgspec.UNSET
    default_cache_ttl: int | msgspec.UnsetType = msgspec.UNSET
