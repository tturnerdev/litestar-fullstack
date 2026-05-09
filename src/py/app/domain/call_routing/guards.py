"""Call routing domain guards."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.lib.guards import require_superuser_access

if TYPE_CHECKING:
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.security.jwt import Token

    from app.db import models as m


def requires_call_routing_access(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the connection user has access to call routing resources.

    Args:
        connection: Request/Connection object.
        _: Route handler.

    Raises:
        PermissionDeniedException: Not authorized
    """
    require_superuser_access(connection, detail="Admin or superuser access is required to manage call routing.")


__all__ = ("requires_call_routing_access",)
