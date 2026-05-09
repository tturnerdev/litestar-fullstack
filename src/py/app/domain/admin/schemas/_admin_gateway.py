"""Admin gateway settings schemas."""

from typing import Annotated

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct


class AdminGatewaySettings(CamelizedBaseStruct, kw_only=True):
    """Current gateway settings returned to the admin UI."""

    default_timeout: int
    default_cache_ttl: int


class AdminGatewaySettingsUpdate(CamelizedBaseStruct, kw_only=True):
    """Payload for updating gateway settings."""

    default_timeout: Annotated[int, Meta(ge=1)] | msgspec.UnsetType = msgspec.UNSET
    default_cache_ttl: Annotated[int, Meta(ge=0)] | msgspec.UnsetType = msgspec.UNSET
