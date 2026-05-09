"""Voicemail domain guards."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.lib import constants

if TYPE_CHECKING:
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.security.jwt import Token

    from app.db import models as m


def _has_system_access(user: m.User) -> bool:
    """Check if user has superuser or system-level access."""
    if user.is_superuser:
        return True
    return any(
        assigned_role.role_name
        for assigned_role in user.roles
        if assigned_role.role_name == constants.SUPERUSER_ACCESS_ROLE
    )


def requires_voicemail_access(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Baseline authentication gate for voicemail endpoints.

    Superusers and system admins pass immediately. Non-superusers are
    permitted here; row-level scoping is enforced by controller query filters.
    """
    if _has_system_access(connection.user):
        return


def requires_voicemail_message_access(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Baseline authentication gate for voicemail message endpoints.

    Superusers and system admins pass immediately. Non-superusers are
    permitted here; row-level scoping is enforced by controller query filters.
    """
    if _has_system_access(connection.user):
        return


__all__ = (
    "requires_voicemail_access",
    "requires_voicemail_message_access",
)
