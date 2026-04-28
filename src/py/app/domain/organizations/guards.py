"""Organization domain guards."""

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


def requires_admin_role(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the connection user is an admin or superuser.

    Admins and superusers can view organization settings.

    Args:
        connection: Request/Connection object.
        _: Route handler.

    Raises:
        PermissionDeniedException: User is not an admin or superuser.
    """
    if connection.user.is_superuser:
        return
    if any(
        assigned_role.role_name
        for assigned_role in connection.user.roles
        if assigned_role.role_name == constants.SUPERUSER_ACCESS_ROLE
    ):
        return
    raise PermissionDeniedException(detail="Insufficient privileges. Admin access required.")


def requires_superuser(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the connection user is a superuser.

    Only superusers can modify organization settings.

    Args:
        connection: Request/Connection object.
        _: Route handler.

    Raises:
        PermissionDeniedException: User is not a superuser.
    """
    if connection.user.is_superuser:
        return
    if any(
        assigned_role.role_name
        for assigned_role in connection.user.roles
        if assigned_role.role_name == constants.SUPERUSER_ACCESS_ROLE
    ):
        return
    raise PermissionDeniedException(detail="Insufficient privileges. Superuser access required.")


__all__ = (
    "requires_admin_role",
    "requires_superuser",
)
