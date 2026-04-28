"""Location domain guards."""

from __future__ import annotations

from typing import TYPE_CHECKING

from litestar.exceptions import PermissionDeniedException

from app.db import models as m
from app.lib import constants

if TYPE_CHECKING:
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.security.jwt import Token


def requires_location_team_membership(
    connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler
) -> None:
    """Verify the connection user is a member of the team that owns the location.

    Args:
        connection: Request/Connection object.
        _: Route handler.

    Raises:
        PermissionDeniedException: Not authorized
    """
    team_id = connection.path_params["team_id"]
    has_system_role = any(
        assigned_role.role_name
        for assigned_role in connection.user.roles
        if assigned_role.role_name == constants.SUPERUSER_ACCESS_ROLE
    )
    has_team_role = any(membership.team.id == team_id for membership in connection.user.teams)
    if connection.user.is_superuser or has_system_role or has_team_role:
        return
    raise PermissionDeniedException(detail="Insufficient permissions to access this location.")


__all__ = ("requires_location_team_membership",)
