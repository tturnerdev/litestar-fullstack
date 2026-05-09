"""Device domain guards."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.lib.guards import require_superuser_access

if TYPE_CHECKING:
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.security.jwt import Token

    from app.db import models as m


def requires_device_ownership(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the connection user owns the device or is a superuser.

    Args:
        connection: Request/Connection object.
        _: Route handler.

    Raises:
        PermissionDeniedException: Not authorized
    """
    require_superuser_access(connection, detail="Admin or superuser access is required to manage devices.")


def requires_device_team_access(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the connection user is a member of the team the device belongs to.

    Args:
        connection: Request/Connection object.
        _: Route handler.

    Raises:
        PermissionDeniedException: Not authorized
    """
    require_superuser_access(connection, detail="You must be a member of the device's team to access it.")


__all__ = (
    "requires_device_ownership",
    "requires_device_team_access",
)
