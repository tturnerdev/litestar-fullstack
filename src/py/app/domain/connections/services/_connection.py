"""Connection service."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class ConnectionService(service.SQLAlchemyAsyncRepositoryService[m.Connection]):
    """Handles CRUD operations on Connection resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.Connection]):
        """Connection Repository."""

        model_type = m.Connection

    repository_type = Repo
    match_fields = ["name", "team_id"]

    async def test_connection(self, connection_id: Any) -> tuple[bool, str | None]:
        """Test connectivity to an external data source.

        Looks up the connection's ``provider`` field and delegates to the
        matching gateway provider's ``health_check`` method when one is
        registered.  Falls back to reporting success for connection types
        that do not have a gateway provider (helpdesk, other, etc.).

        Args:
            connection_id: The primary key of the connection to test.

        Returns:
            A tuple of (success, error_message).
        """
        db_obj = await self.get(connection_id)
        now = datetime.now(tz=timezone.utc)

        # Lazy import to avoid circular dependency between domains.
        from app.domain.gateway.providers import get_provider

        provider_cls = get_provider(db_obj.provider)
        if provider_cls is not None:
            provider = provider_cls()
            success, error_message = await provider.health_check(db_obj)
        else:
            # No gateway provider registered for this connection type;
            # fall back to optimistic success.
            success = True
            error_message = None

        if success:
            db_obj.status = m.ConnectionStatus.CONNECTED
            db_obj.last_health_check = now
            db_obj.last_error = None
        else:
            db_obj.status = m.ConnectionStatus.ERROR
            db_obj.last_health_check = now
            db_obj.last_error = error_message

        await self.repository.update(db_obj)
        return success, error_message
