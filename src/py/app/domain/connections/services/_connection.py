"""Connection service."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Sequence
from uuid import UUID

from advanced_alchemy.extensions.litestar import repository, service
from sqlalchemy import func, select

from app.db import models as m
from app.domain.connections.schemas import ConnectionDetail, ConnectionList


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

    async def get_device_count(self, connection_id: UUID) -> int:
        """Get the number of devices managed by a connection.

        Args:
            connection_id: Connection ID

        Returns:
            Number of devices managed by this connection.
        """
        result = await self.repository.session.execute(
            select(func.count(m.Device.id)).where(m.Device.connection_id == connection_id),
        )
        return result.scalar_one()

    async def get_device_counts(self, connection_ids: Sequence[UUID]) -> dict[UUID, int]:
        """Get device counts for multiple connections in a single query.

        Args:
            connection_ids: Sequence of connection IDs.

        Returns:
            Mapping of connection_id to device count.
        """
        if not connection_ids:
            return {}
        result = await self.repository.session.execute(
            select(m.Device.connection_id, func.count(m.Device.id))
            .where(m.Device.connection_id.in_(connection_ids))
            .group_by(m.Device.connection_id),
        )
        counts = dict(result.all())
        return {cid: counts.get(cid, 0) for cid in connection_ids}

    async def to_schema_enriched(
        self,
        obj: m.Connection | Sequence[m.Connection],
        total: int | None = None,
        filters: Any | None = None,
        *,
        schema_type: type[ConnectionList] | type[ConnectionDetail] = ConnectionList,
    ) -> Any:
        """Convert model(s) to schema with computed managed_device_count.

        Args:
            obj: Single model or sequence of models.
            total: Total count for pagination.
            filters: Filters for pagination.
            schema_type: Schema class to use.

        Returns:
            Schema or paginated schema response.
        """
        if isinstance(obj, m.Connection):
            schema = self.to_schema(obj, schema_type=schema_type)
            count = await self.get_device_count(obj.id)
            object.__setattr__(schema, "managed_device_count", count)
            return schema

        if total is not None and filters is not None:
            paginated = self.to_schema(obj, total, filters, schema_type=schema_type)
            conn_ids = [conn.id for conn in obj]
            counts = await self.get_device_counts(conn_ids)
            for conn_model, conn_schema in zip(obj, paginated.items, strict=False):
                object.__setattr__(conn_schema, "managed_device_count", counts.get(conn_model.id, 0))
            return paginated

        schemas = []
        conn_ids = [conn.id for conn in obj]
        counts = await self.get_device_counts(conn_ids)
        for item in obj:
            schema = self.to_schema(item, schema_type=schema_type)
            object.__setattr__(schema, "managed_device_count", counts.get(item.id, 0))
            schemas.append(schema)
        return schemas
