"""Voice domain guards."""

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


def requires_extension_ownership(
    connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler
) -> None:
    """Verify the connection user owns the extension or is superuser."""
    if connection.user.is_superuser:
        return
    has_system_role = any(
        assigned_role.role_name
        for assigned_role in connection.user.roles
        if assigned_role.role_name == constants.SUPERUSER_ACCESS_ROLE
    )
    if has_system_role:
        return
    raise PermissionDeniedException(detail="Insufficient permissions to access this extension.")


def requires_phone_number_access(
    connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler
) -> None:
    """Verify the connection user owns the phone number or has team access."""
    if connection.user.is_superuser:
        return
    has_system_role = any(
        assigned_role.role_name
        for assigned_role in connection.user.roles
        if assigned_role.role_name == constants.SUPERUSER_ACCESS_ROLE
    )
    if has_system_role:
        return
    raise PermissionDeniedException(detail="Insufficient permissions to access this phone number.")


__all__ = (
    "requires_extension_ownership",
    "requires_phone_number_access",
)
