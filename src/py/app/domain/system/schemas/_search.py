"""Global search response schemas."""

from __future__ import annotations

from app.lib.schema import CamelizedBaseStruct


class SearchResultItem(CamelizedBaseStruct, kw_only=True):
    """A single search result."""

    type: str
    """Entity type (e.g. 'device', 'team', 'ticket')."""
    id: str
    """Entity primary key as a string."""
    label: str
    """Human-readable label for the result."""
    description: str
    """Short secondary text (e.g. type info, status)."""
    url: str
    """Frontend route path for navigating to the entity."""


class SearchResponse(CamelizedBaseStruct, kw_only=True):
    """Grouped search results from the global search endpoint."""

    query: str
    """The original search query."""
    results: list[SearchResultItem]
    """Flat list of search results, ordered by type."""
    total: int
    """Total number of results returned."""
