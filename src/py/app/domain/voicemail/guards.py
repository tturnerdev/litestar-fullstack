"""Voicemail domain guards."""

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


def _has_system_access(user: m.User) -> bool:
    """Check if user has superuser or system-level access."""
    if user.is_superuser:
        return True
    return any(
        assigned_role.role_name
        for assigned_role in user.roles
        if assigned_role.role_name == constants.SUPERUSER_ACCESS_ROLE
    )


def requires_voicemail_access(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the connection user has voicemail access.

    Superusers and system admins pass immediately. For regular users,
    row-level access is enforced in the controller via query filters.

    Args:
        connection: Request/Connection object.
        _: Route handler.

    Raises:
        PermissionDeniedException: Not authorized
    """
    if _has_system_access(connection.user):
        return
    # For non-superusers, we allow access here and rely on controller query filters
    # to scope results to voicemail boxes belonging to the user's extensions.


def requires_voicemail_message_access(
    connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler
) -> None:
    """Verify the connection user has access to voicemail messages.

    Superusers and system admins pass immediately. For regular users,
    row-level access is enforced in the controller.

    Args:
        connection: Request/Connection object.
        _: Route handler.

    Raises:
        PermissionDeniedException: Not authorized
    """
    if _has_system_access(connection.user):
        return
    # For non-superusers, we allow access here and rely on controller query filters
    # to scope results to messages belonging to the user's voicemail boxes.


__all__ = (
    "requires_voicemail_access",
    "requires_voicemail_message_access",
)
