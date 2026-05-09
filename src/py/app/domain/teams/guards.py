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

    If no ``TeamRolePermission`` row exists for a membership, the default
    behaviour is:
        - ADMIN  -> allowed
        - MEMBER -> denied

    Superusers always bypass the check.

    Args:
        feature_area: The FeatureArea value (e.g. ``"DEVICES"``, ``"VOICE"``).
        action: ``"view"`` or ``"edit"``.

    Returns:
        An async guard function compatible with Litestar's ``guards`` parameter.
    """
    # Normalise to uppercase to match FeatureArea enum values stored in the DB.
    feature_area_upper = feature_area.upper()

    async def _guard(
        connection: ASGIConnection[Any, m.User, Token, Any],
        _: BaseRouteHandler,
    ) -> None:
        user: m.User = connection.user

        # Superusers bypass all permission checks.
        if has_superuser_access(connection):
            return

        # No team memberships -> deny.
        if not user.teams:
            raise PermissionDeniedException(
                detail=f"No team membership found. Access to {feature_area} requires a team role."
            )

        # Obtain a database session from the connection to query permission rows.
        from app.config import alchemy

        session = alchemy.provide_session(connection.app.state, connection.scope)

        # Gather team_id -> role from the user's memberships.
        membership_map: dict[Any, m.TeamRoles] = {membership.team_id: membership.role for membership in user.teams}

        # Query permission entries for the user's teams and the requested feature area.
        stmt = select(m.TeamRolePermission).where(
            m.TeamRolePermission.team_id.in_(membership_map.keys()),
            m.TeamRolePermission.feature_area == feature_area_upper,
        )
        result = await session.execute(stmt)
        permission_rows = result.scalars().all()

        # Build a lookup: (team_id, role) -> permission row
        perm_lookup: dict[tuple[Any, str], m.TeamRolePermission] = {
            (row.team_id, row.role): row for row in permission_rows
        }

        # Check each membership: if ANY team grants the permission, allow.
        for team_id, role in membership_map.items():
            perm = perm_lookup.get((team_id, role))
            if perm is not None:
                # Explicit permission entry exists — check the column.
                allowed = perm.can_edit if action == "edit" else perm.can_view
                if allowed:
                    return
            # No entry exists — apply default: ADMIN=allow, MEMBER=deny.
            elif role == m.TeamRoles.ADMIN:
                return
                # MEMBER without explicit entry -> denied for this team, continue checking.

        raise PermissionDeniedException(detail=f"You do not have {action} permission for {feature_area}.")

    return _guard


__all__ = (
    "requires_feature_permission",
    "requires_team_admin",
    "requires_team_membership",
    "requires_team_ownership",
)
