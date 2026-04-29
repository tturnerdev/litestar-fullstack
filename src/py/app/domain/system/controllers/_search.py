"""Global search controller."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from uuid import UUID

import structlog
from litestar import Controller, get
from sqlalchemy import or_, select

from app.db import models as m
from app.domain.system.schemas._search import SearchResponse, SearchResultItem

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger()

# Maximum results per entity type.
_PER_TYPE_LIMIT = 5
# Maximum total results returned.
_TOTAL_LIMIT = 20


@dataclass(frozen=True)
class _SearchableEntity:
    """Describes how to search a single entity type."""

    type_name: str
    """Identifier used in the response (e.g. 'device', 'team')."""
    model_path: str
    """Dotted import path to the SQLAlchemy model class."""
    search_fields: tuple[str, ...]
    """Column names to match with ILIKE."""
    label_field: str
    """Column name used as the human-readable label."""
    description_field: str
    """Column name used as secondary description text."""
    url_template: str
    """Python format string for the frontend URL. Receives 'id' as keyword arg."""
    superuser_only: bool = False
    """If True, only superusers can see results from this entity."""
    scoped_fields: tuple[str, ...] = field(default_factory=tuple)
    """Fields that scope access (e.g. 'user_id', 'team_id').
    If non-empty, non-superusers only see rows they own or belong to via team membership."""


# ---------------------------------------------------------------------------
# Search registry
#
# Each entry defines a searchable entity. Models are imported lazily so the
# controller file can be loaded even if some domain models haven't been
# created yet.
# ---------------------------------------------------------------------------
_SEARCH_REGISTRY: list[_SearchableEntity] = [
    _SearchableEntity(
        type_name="team",
        model_path="app.db.models.Team",
        search_fields=("name",),
        label_field="name",
        description_field="description",
        url_template="/teams/{id}",
        scoped_fields=(),  # Access filtered by team membership in code
    ),
    _SearchableEntity(
        type_name="device",
        model_path="app.db.models.Device",
        search_fields=("name",),
        label_field="name",
        description_field="device_type",
        url_template="/devices/{id}",
        scoped_fields=("user_id", "team_id"),
    ),
    _SearchableEntity(
        type_name="ticket",
        model_path="app.db.models.Ticket",
        search_fields=("subject", "ticket_number"),
        label_field="subject",
        description_field="ticket_number",
        url_template="/support/{id}",
        scoped_fields=("user_id", "team_id"),
    ),
    _SearchableEntity(
        type_name="extension",
        model_path="app.db.models.Extension",
        search_fields=("extension_number", "display_name"),
        label_field="display_name",
        description_field="extension_number",
        url_template="/voice/extensions/{id}",
        scoped_fields=("user_id",),
    ),
    _SearchableEntity(
        type_name="phone_number",
        model_path="app.db.models.PhoneNumber",
        search_fields=("number", "label"),
        label_field="number",
        description_field="label",
        url_template="/voice/phone-numbers",
        scoped_fields=("user_id", "team_id"),
    ),
    _SearchableEntity(
        type_name="fax_number",
        model_path="app.db.models.FaxNumber",
        search_fields=("number", "label"),
        label_field="number",
        description_field="label",
        url_template="/fax/numbers/{id}",
        scoped_fields=("user_id", "team_id"),
    ),
    _SearchableEntity(
        type_name="location",
        model_path="app.db.models.Location",
        search_fields=("name",),
        label_field="name",
        description_field="description",
        url_template="/teams/{team_id}",
        scoped_fields=("team_id",),
    ),
    _SearchableEntity(
        type_name="user",
        model_path="app.db.models.User",
        search_fields=("name", "email"),
        label_field="name",
        description_field="email",
        url_template="/admin/users",
        superuser_only=True,
    ),
]


def _import_class(dotted_path: str) -> type:
    """Import a class from a dotted path like 'app.db.models.Team'.

    Args:
        dotted_path: Fully-qualified dotted import path.

    Returns:
        The imported class.
    """
    import importlib

    module_path, _, class_name = dotted_path.rpartition(".")
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


def _get_user_team_ids(user: m.User) -> set[UUID]:
    """Extract all team IDs the user is a member of.

    Args:
        user: The current user model instance.

    Returns:
        Set of team UUIDs.
    """
    return {membership.team_id for membership in (user.teams or [])}


async def _search_entity(
    db_session: AsyncSession,
    entry: _SearchableEntity,
    query: str,
    user: m.User,
    limit: int,
) -> list[SearchResultItem]:
    """Search a single entity type and return matching results.

    Args:
        db_session: Active async database session.
        entry: The search registry entry for this entity type.
        query: The user's search string.
        user: The authenticated user.
        limit: Maximum number of results.

    Returns:
        List of search result items.
    """
    try:
        model_cls = _import_class(entry.model_path)
    except (ImportError, AttributeError):
        await logger.awarning("Search entity not available", entity=entry.type_name)
        return []

    # Build ILIKE conditions across all search fields.
    pattern = f"%{query}%"
    ilike_conditions = []
    for field_name in entry.search_fields:
        col = getattr(model_cls, field_name, None)
        if col is not None:
            ilike_conditions.append(col.ilike(pattern))

    if not ilike_conditions:
        return []

    stmt = select(model_cls).where(or_(*ilike_conditions))

    # Apply access scoping for non-superusers.
    if not user.is_superuser and entry.scoped_fields:
        team_ids = _get_user_team_ids(user)
        access_conditions: list[Any] = []
        for scope_field in entry.scoped_fields:
            col = getattr(model_cls, scope_field, None)
            if col is None:
                continue
            if scope_field == "user_id":
                access_conditions.append(col == user.id)
            elif scope_field == "team_id":
                if team_ids:
                    access_conditions.append(col.in_(team_ids))
        if access_conditions:
            stmt = stmt.where(or_(*access_conditions))
        else:
            # User has no teams and no user_id scope -- return nothing.
            return []

    # Special case: team access for non-superusers.
    if entry.type_name == "team" and not user.is_superuser:
        team_ids = _get_user_team_ids(user)
        if team_ids:
            stmt = stmt.where(model_cls.id.in_(team_ids))
        else:
            return []

    stmt = stmt.limit(limit)
    result = await db_session.execute(stmt)
    rows = result.scalars().all()

    items: list[SearchResultItem] = []
    for row in rows:
        label_val = getattr(row, entry.label_field, None) or ""
        desc_val = getattr(row, entry.description_field, None) or ""
        row_id = str(row.id)

        # Build URL using available row attributes.
        url_kwargs: dict[str, str] = {"id": row_id}
        if hasattr(row, "team_id") and row.team_id:
            url_kwargs["team_id"] = str(row.team_id)

        try:
            url = entry.url_template.format(**url_kwargs)
        except KeyError:
            url = entry.url_template.format(id=row_id)

        items.append(
            SearchResultItem(
                type=entry.type_name,
                id=row_id,
                label=str(label_val),
                description=str(desc_val),
                url=url,
            )
        )

    return items


class SearchController(Controller):
    """Global search across all entity types."""

    tags = ["System"]

    @get(
        operation_id="GlobalSearch",
        name="system:global-search",
        path="/api/search",
        summary="Global Search",
    )
    async def global_search(
        self,
        db_session: AsyncSession,
        current_user: m.User,
        q: str = "",
        limit: int = 5,
    ) -> SearchResponse:
        """Search across all entity types.

        Args:
            db_session: The database session.
            current_user: The authenticated user.
            q: Search query string.
            limit: Maximum results per entity type (default 5, max 10).

        Returns:
            SearchResponse with grouped results.
        """
        query = q.strip()
        if not query or len(query) < 2:
            return SearchResponse(query=q, results=[], total=0)

        per_type_limit = min(limit, 10)
        all_results: list[SearchResultItem] = []

        for entry in _SEARCH_REGISTRY:
            # Skip superuser-only entities for regular users.
            if entry.superuser_only and not current_user.is_superuser:
                continue

            # Respect total limit.
            remaining = _TOTAL_LIMIT - len(all_results)
            if remaining <= 0:
                break

            effective_limit = min(per_type_limit, remaining)
            items = await _search_entity(
                db_session,
                entry,
                query,
                current_user,
                effective_limit,
            )
            all_results.extend(items)

        await logger.ainfo(
            "Global search",
            query=query,
            result_count=len(all_results),
            user_id=str(current_user.id),
        )

        return SearchResponse(
            query=query,
            results=all_results,
            total=len(all_results),
        )
