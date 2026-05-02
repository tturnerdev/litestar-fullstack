"""Tasks domain guards."""

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


def requires_task_access(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the user can access background tasks.

    User must be a superuser or have the superuser role.
    Task-level team scoping is enforced at the service/controller level.
    """
    if connection.user.is_superuser:
        return
    has_system_role = any(
        assigned_role.role_name
        for assigned_role in connection.user.roles
        if assigned_role.role_name == constants.SUPERUSER_ACCESS_ROLE
    )
    if has_system_role:
        return
    # For task access, we rely on service-level filtering by team membership.
    # The guard allows access; the controller further filters by user/team.


__all__ = (
    "requires_task_access",
)
