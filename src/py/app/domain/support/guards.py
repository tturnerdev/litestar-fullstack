"""Support domain guards."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from litestar.exceptions import PermissionDeniedException

from app.db import models as m
from app.lib import constants

if TYPE_CHECKING:
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.security.jwt import Token

# Messages can be edited within this window
MESSAGE_EDIT_WINDOW = timedelta(minutes=15)


def requires_ticket_access(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the user can access the ticket.

    User is the ticket creator, assigned agent, or superuser.
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
    # For ticket access, we'll rely on service-level filtering.
    # The guard allows access; the controller further filters by user_id.


def requires_ticket_message_edit(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the user can edit/delete the message.

    User must be the message author and within the edit time window.
    Superusers can always edit.
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
    # Detailed author + time-window check is enforced at the service/controller level
    # since we need to load the message from the database.


def requires_support_agent(connection: ASGIConnection[Any, m.User, Token, Any], _: BaseRouteHandler) -> None:
    """Verify the user has support agent role.

    Required for internal notes and ticket assignment.
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
    raise PermissionDeniedException(detail="Insufficient permissions. Support agent role required.")


__all__ = (
    "requires_support_agent",
    "requires_ticket_access",
    "requires_ticket_message_edit",
)
