"""Analytics domain guards."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.lib.guards import has_superuser_access

if TYPE_CHECKING:
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.security.jwt import Token

    from app.db import models as m


def requires_analytics_access(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the connection user has access to analytics data.

    Superusers and system admins pass immediately. For non-superusers,
    access is deferred to controller-level query filters which scope
    results to the user's team memberships.

    Args:
        connection: Request/Connection object.
        _: Route handler.

    Raises:
        PermissionDeniedException: Not authorized
    """
    if has_superuser_access(connection):
        return


__all__ = ("requires_analytics_access",)
