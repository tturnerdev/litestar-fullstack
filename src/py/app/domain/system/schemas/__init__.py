"""System domain schemas."""

from app.domain.system.schemas._health import OAuthConfig, SystemHealth
from app.domain.system.schemas._sync import SyncResponse

__all__ = (
    "OAuthConfig",
    "SyncResponse",
    "SystemHealth",
)
