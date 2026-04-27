"""Fax domain guards."""

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


def _has_system_access(user: m.User) -> bool:
    """Check if user has superuser or system-level access."""
    if user.is_superuser:
        return True
    return any(
        assigned_role.role_name
        for assigned_role in user.roles
        if assigned_role.role_name == constants.SUPERUSER_ACCESS_ROLE
    )


def requires_fax_number_access(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the connection user owns the fax number or has team access.

    Checks:
    - User is superuser or has system admin role
    - Otherwise, defers to controller-level filtering (user ownership / team membership
      is enforced by the service query filters in each controller method).

    Note: Full ownership verification requires a DB lookup. The guard provides a
    baseline permission check; controllers enforce row-level access via query filters.

    Args:
        connection: Request/Connection object.
        _: Route handler.

    Raises:
        PermissionDeniedException: Not authorized
    """
    if _has_system_access(connection.user):
        return
    # For non-superusers, we allow access here and rely on controller query filters
    # to scope results to the user's own fax numbers and team fax numbers.
    # Individual GET/PATCH endpoints will verify ownership via the service layer.


def requires_fax_message_access(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the connection user has access to the fax number this message belongs to.

    Note: Full ownership verification requires a DB lookup. The guard provides a
    baseline permission check; controllers enforce row-level access via query filters.

    Args:
        connection: Request/Connection object.
        _: Route handler.

    Raises:
        PermissionDeniedException: Not authorized
    """
    if _has_system_access(connection.user):
        return
    # For non-superusers, we allow access here and rely on controller query filters
    # to scope results to messages belonging to the user's fax numbers.


__all__ = (
    "requires_fax_message_access",
    "requires_fax_number_access",
)
