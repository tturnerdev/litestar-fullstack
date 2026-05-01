"""E911 domain guards."""

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


def requires_team_membership(
    connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler
) -> None:
    """Verify the connection user has at least one team membership.

    E911 registrations are team-scoped, so the user must belong to
    the team that owns the registration.

    Args:
        connection: Request/Connection object.
        _: Route handler.

    Raises:
        PermissionDeniedException: Not authorized
    """
    has_system_role = any(
        assigned_role.role_name
        for assigned_role in connection.user.roles
        if assigned_role.role_name == constants.SUPERUSER_ACCESS_ROLE
    )
    if connection.user.is_superuser or has_system_role:
        return
    if connection.user.teams:
        return
    raise PermissionDeniedException(detail="Insufficient permissions to manage E911 registrations.")


__all__ = ("requires_team_membership",)
