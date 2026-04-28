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

        This is a stub that can be extended with actual connectivity checks
        per provider type (HTTP ping, DB connect, API health endpoint, etc.).

        Args:
            connection_id: The primary key of the connection to test.

        Returns:
            A tuple of (success, error_message).
        """
        db_obj = await self.get(connection_id)
        now = datetime.now(tz=timezone.utc)

        # Stub: always reports success. Replace with real provider checks.
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
