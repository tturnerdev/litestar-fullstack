"""Connections domain guards."""

from __future__ import annotations

from typing import TYPE_CHECKING

from litestar.exceptions import PermissionDeniedException

from app.lib import constants

if TYPE_CHECKING:
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.security.jwt import Token

    from app.db import models as m


def requires_connections_admin(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the user has admin-level access to manage connections.

    Connections contain sensitive credentials (API keys, passwords), so only
    superusers and users with the superuser role can manage them.

    Args:
        connection: Request/Connection object.
        _: Route handler.

    Raises:
        PermissionDeniedException: Not authorized
    """
    if connection.user.is_superuser:
        return
    has_system_role = any(
        assigned_role.role_name
        for assigned_role in connection.user.roles
        if assigned_role.role_name == constants.SUPERUSER_ACCESS_ROLE
    )
    if has_system_role:
        return
    raise PermissionDeniedException(detail="Insufficient permissions. Admin access is required to manage connections.")


__all__ = ("requires_connections_admin",)
