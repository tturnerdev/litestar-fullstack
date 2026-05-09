"""Shared guard utilities for domain guards."""

from __future__ import annotations

from typing import TYPE_CHECKING

from litestar.exceptions import PermissionDeniedException

from app.lib import constants

if TYPE_CHECKING:
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.security.jwt import Token

    from app.db import models as m


def has_superuser_access(connection: ASGIConnection[Any, m.User, Token, Any]) -> bool:
    """Check if the connection user has superuser or system admin access."""
    if connection.user.is_superuser:
        return True
    return any(assigned_role.role_name == constants.SUPERUSER_ACCESS_ROLE for assigned_role in connection.user.roles)


def require_superuser_access(
    connection: ASGIConnection[Any, m.User, Token, Any],
    detail: str = "Admin or superuser access is required.",
) -> None:
    """Raise PermissionDeniedException if the user lacks superuser access."""
    if not has_superuser_access(connection):
        raise PermissionDeniedException(detail=detail)


__all__ = (
    "has_superuser_access",
    "require_superuser_access",
)
