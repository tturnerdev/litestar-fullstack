"""System status schemas."""

from typing import Literal

from app.__metadata__ import __version__
from app.lib.schema import CamelizedBaseStruct


class SystemHealth(CamelizedBaseStruct, kw_only=True):
    """System health check response."""

    app: str
    database_status: Literal["online", "offline"] = "offline"
    version: str = __version__


class OAuthConfig(CamelizedBaseStruct, kw_only=True):
    """OAuth provider configuration for frontend."""

    google_enabled: bool = False
    github_enabled: bool = False
