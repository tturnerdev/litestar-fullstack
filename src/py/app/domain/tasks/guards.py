"""Tasks domain guards."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.lib.guards import has_superuser_access

if TYPE_CHECKING:
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.security.jwt import Token

    from app.db import models as m


def requires_task_access(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Baseline authentication gate for background task endpoints.

    Superusers pass immediately. Non-superusers are permitted here;
    team-level scoping is enforced by service query filters.
    """
    if has_superuser_access(connection):
        return


__all__ = ("requires_task_access",)
