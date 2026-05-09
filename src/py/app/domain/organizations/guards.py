"""Organization domain guards."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.lib.guards import require_superuser_access

if TYPE_CHECKING:
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.security.jwt import Token

    from app.db import models as m


def requires_admin_role(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the connection user is an admin or superuser.

    Admins and superusers can view organization settings.

    Args:
        connection: Request/Connection object.
        _: Route handler.

    Raises:
        PermissionDeniedException: User is not an admin or superuser.
    """
    require_superuser_access(connection, detail="Insufficient privileges. Admin access required.")


__all__ = ("requires_admin_role",)
