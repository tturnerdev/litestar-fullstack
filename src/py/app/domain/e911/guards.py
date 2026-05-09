"""E911 domain guards."""

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


def requires_team_membership(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the connection user has at least one team membership.

    E911 registrations are team-scoped, so the user must belong to
    the team that owns the registration.

    Args:
        connection: Request/Connection object.
        _: Route handler.

    Raises:
        PermissionDeniedException: Not authorized
    """
    if has_superuser_access(connection):
        return
    if connection.user.teams:
        return
    raise PermissionDeniedException(detail="A team membership is required to manage E911 registrations.")


__all__ = ("requires_team_membership",)
