"""Webhook domain guards."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.lib.guards import require_superuser_access

if TYPE_CHECKING:
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.security.jwt import Token

    from app.db import models as m


def requires_webhook_ownership(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the connection user owns the webhook or is a superuser.

    Args:
        connection: Request/Connection object.
        _: Route handler.

    Raises:
        PermissionDeniedException: Not authorized
    """
    require_superuser_access(connection, detail="Admin or superuser access is required to manage webhooks.")


__all__ = ("requires_webhook_ownership",)
