"""Team domain guards."""

from __future__ import annotations

from typing import TYPE_CHECKING

from litestar.exceptions import PermissionDeniedException
from sqlalchemy import select

from app.db import models as m
from app.lib.guards import has_superuser_access

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.security.jwt import Token


def requires_team_membership(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the connection user is a member of the team.

    Args:
        connection (ASGIConnection): Request/Connection object.
        _ (BaseRouteHandler): Route handler.

    Raises:
        PermissionDeniedException: Not authorized
    """
    team_id = connection.path_params["team_id"]
    has_team_role = any(membership.team.id == team_id for membership in connection.user.teams)
    if has_superuser_access(connection) or has_team_role:
        return
    raise PermissionDeniedException(detail="You must be a member of this team to access it.")


def requires_team_admin(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the connection user is a team admin.

    Args:
        connection (ASGIConnection): Request/Connection object.
        _ (BaseRouteHandler): Route handler.

    Raises:
        PermissionDeniedException: Not authorized
    """
    team_id = connection.path_params["team_id"]
    has_team_role = any(
        membership.team.id == team_id and membership.role == m.TeamRoles.ADMIN for membership in connection.user.teams
    )
    if has_superuser_access(connection) or has_team_role:
        return
    raise PermissionDeniedException(detail="Team admin role is required for this action.")


def requires_team_ownership(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify that the connection user is the team owner.

    Args:
        connection (ASGIConnection): Request/Connection object.
        _ (BaseRouteHandler): Route handler.

    Raises:
        PermissionDeniedException: Not authorized
    """
    team_id = connection.path_params["team_id"]
    has_team_role = any(membership.team.id == team_id and membership.is_owner for membership in connection.user.teams)
    if has_superuser_access(connection) or has_team_role:
        return

    raise PermissionDeniedException(detail="Team owner role is required for this action.")


def requires_feature_permission(
    feature_area: str,
    action: str = "view",
) -> Callable[
    [ASGIConnection[Any, m.User, Token, Any], BaseRouteHandler],
    Coroutine[Any, Any, None],
]:
    """Create a guard that checks TeamRolePermission entries.

    The returned async guard verifies the current user holds the requested
    permission (``can_view`` or ``can_edit``) for *feature_area* in at least
    one of their team memberships.

    Sub-features (e.g. ``VOICE_PHONE_NUMBERS``) fall back to their parent
    feature (``VOICE``) when no explicit sub-feature permission row exists.

    If no ``TeamRolePermission`` row exists for a membership, the default
    behaviour is:
        - ADMIN  -> allowed
        - MEMBER -> denied

    Superusers always bypass the check.

    Args:
        feature_area: The FeatureArea value (e.g. ``"DEVICES"``, ``"VOICE_EXTENSIONS"``).
        action: ``"view"`` or ``"edit"``.

    Returns:
        An async guard function compatible with Litestar's ``guards`` parameter.
    """
    from app.db.models._feature_area import FEATURE_PARENT_MAP

    feature_area_upper = feature_area.upper()
    parent_area = FEATURE_PARENT_MAP.get(feature_area_upper)

    async def _guard(
        connection: ASGIConnection[Any, m.User, Token, Any],
        _: BaseRouteHandler,
    ) -> None:
        user: m.User = connection.user

        if has_superuser_access(connection):
            return

        if not user.teams:
            raise PermissionDeniedException(
                detail=f"No team membership found. Access to {feature_area} requires a team role."
            )

        from app.config import alchemy

        membership_map: dict[Any, m.TeamRoles] = {membership.team_id: membership.role for membership in user.teams}

        areas_to_check = [feature_area_upper]
        if parent_area:
            areas_to_check.append(parent_area)

        stmt = select(m.TeamRolePermission).where(
            m.TeamRolePermission.team_id.in_(membership_map.keys()),
            m.TeamRolePermission.feature_area.in_(areas_to_check),
        )
        async with alchemy.get_session() as session:
            result = await session.execute(stmt)
            permission_rows = result.scalars().all()

        perm_lookup: dict[tuple[Any, str, str], m.TeamRolePermission] = {
            (row.team_id, row.role, row.feature_area): row for row in permission_rows
        }

        for team_id, role in membership_map.items():
            # Check sub-feature first, then parent.
            perm = perm_lookup.get((team_id, role, feature_area_upper))
            if perm is None and parent_area:
                perm = perm_lookup.get((team_id, role, parent_area))

            if perm is not None:
                allowed = perm.can_edit if action == "edit" else perm.can_view
                if allowed:
                    return
            elif role == m.TeamRoles.ADMIN:
                return

        raise PermissionDeniedException(detail=f"You do not have {action} permission for {feature_area}.")

    return _guard


__all__ = (
    "requires_feature_permission",
    "requires_team_admin",
    "requires_team_membership",
    "requires_team_ownership",
)
