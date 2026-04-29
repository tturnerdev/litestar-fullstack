"""System domain schemas."""

from app.domain.system.schemas._health import OAuthConfig, SystemHealth
from app.domain.system.schemas._search import SearchResponse, SearchResultItem
from app.domain.system.schemas._sync import SyncResponse

__all__ = (
    "OAuthConfig",
    "SearchResponse",
    "SearchResultItem",
    "SyncResponse",
    "SystemHealth",
)
