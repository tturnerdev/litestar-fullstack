"""Voice domain guards."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.lib.guards import require_superuser_access

if TYPE_CHECKING:
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.security.jwt import Token

    from app.db import models as m


def requires_extension_ownership(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the connection user owns the extension or is superuser."""
    require_superuser_access(connection, detail="Admin or superuser access is required to manage this extension.")


def requires_phone_number_access(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the connection user owns the phone number or has team access."""
    require_superuser_access(connection, detail="Admin or superuser access is required to manage this phone number.")


__all__ = (
    "requires_extension_ownership",
    "requires_phone_number_access",
)
