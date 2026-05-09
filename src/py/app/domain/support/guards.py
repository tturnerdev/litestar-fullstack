"""Support domain guards."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from app.lib.guards import has_superuser_access, require_superuser_access

if TYPE_CHECKING:
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.security.jwt import Token

    from app.db import models as m

# Messages can be edited within this window
MESSAGE_EDIT_WINDOW = timedelta(minutes=15)


def requires_ticket_access(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Baseline authentication gate for ticket endpoints.

    Superusers pass immediately. Non-superusers are permitted here;
    row-level scoping (creator, assigned agent) is enforced by service query filters.
    """
    if has_superuser_access(connection):
        return


def requires_ticket_message_edit(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Baseline authentication gate for ticket message edit/delete.

    Superusers pass immediately. Non-superusers are permitted here;
    author and edit-window checks are enforced at the service layer.
    """
    if has_superuser_access(connection):
        return


def requires_support_agent(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the user has support agent role.

    Required for internal notes and ticket assignment.
    """
    require_superuser_access(connection, detail="Insufficient permissions. Support agent role required.")


__all__ = (
    "requires_support_agent",
    "requires_ticket_access",
    "requires_ticket_message_edit",
)
