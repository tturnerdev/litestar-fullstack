"""Events domain guards."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.security.jwt import Token

    from app.db import models as m


def requires_active_session(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the user has an active session for SSE streaming.

    JWT auth is already enforced by the ``_app`` route guard.
    This guard exists as an explicit marker for the SSE endpoint
    and can be extended later for connection-level rate limiting.
    """


__all__ = ("requires_active_session",)
