"""Location domain guards."""

from __future__ import annotations

from typing import TYPE_CHECKING

from litestar.exceptions import PermissionDeniedException

from app.lib.guards import has_superuser_access

if TYPE_CHECKING:
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.security.jwt import Token

    from app.db import models as m


def requires_location_team_membership(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the connection user is a member of the team that owns the location.

    Args:
        connection: Request/Connection object.
        _: Route handler.

    Raises:
        PermissionDeniedException: Not authorized
    """
    team_id = connection.path_params["team_id"]
    has_team_role = any(membership.team.id == team_id for membership in connection.user.teams)
    if has_superuser_access(connection) or has_team_role:
        return
    raise PermissionDeniedException(detail="You must be a member of this team to access its locations.")


__all__ = ("requires_location_team_membership",)
