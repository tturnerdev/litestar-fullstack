"""Connection Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.params import Dependency, Parameter

from app.db import models as m
from app.domain.connections.guards import requires_connections_admin
from app.domain.connections.schemas import ConnectionCreate, ConnectionDetail, ConnectionList, ConnectionUpdate
from app.domain.connections.services import ConnectionService
from app.lib.deps import create_service_dependencies
from app.lib.schema import Message

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination


def _mask_credentials(db_obj: m.Connection) -> list[str]:
    """Extract credential field names without exposing values.

    Args:
        db_obj: The connection database object.

    Returns:
        A list of field names present in the credentials dict.
    """
    if db_obj.credentials and isinstance(db_obj.credentials, dict):
        return list(db_obj.credentials.keys())
    return []


class ConnectionController(Controller):
    """Connections."""

    tags = ["Connections"]
    guards = [requires_connections_admin]
    dependencies = create_service_dependencies(
        ConnectionService,
        key="connections_service",
        filters={
            "id_filter": UUID,
            "search": "name",
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "name",
            "sort_order": "asc",
        },
    )

    @get(operation_id="ListConnections", path="/api/connections")
    async def list_connections(
        self,
        connections_service: ConnectionService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
        team_id: Annotated[UUID | None, Parameter(query="teamId", required=False)] = None,
    ) -> OffsetPagination[ConnectionList]:
        """List connections, optionally filtered by team.

        Args:
            connections_service: Connection Service
            current_user: Current User
            filters: Filters
            team_id: Optional team ID filter

        Returns:
            OffsetPagination[ConnectionList]
        """
        extra_filters = []
        if team_id is not None:
            extra_filters.append(m.Connection.team_id == team_id)
        results, total = await connections_service.list_and_count(*filters, *extra_filters)
        return connections_service.to_schema(results, total, filters, schema_type=ConnectionList)

    @post(operation_id="CreateConnection", path="/api/connections")
    async def create_connection(
        self,
        connections_service: ConnectionService,
        current_user: m.User,
        data: ConnectionCreate,
    ) -> ConnectionList:
        """Create a new connection.

        Args:
            connections_service: Connection Service
            current_user: Current User
            data: Connection Create

        Returns:
            ConnectionList
        """
        obj = data.to_dict()
        db_obj = await connections_service.create(obj)
        return connections_service.to_schema(db_obj, schema_type=ConnectionList)

    @get(
        operation_id="GetConnection",
        path="/api/connections/{connection_id:uuid}",
    )
    async def get_connection(
        self,
        connections_service: ConnectionService,
        connection_id: Annotated[UUID, Parameter(title="Connection ID", description="The connection to retrieve.")],
    ) -> ConnectionDetail:
        """Get connection details.

        Credential values are never returned — only field names.

        Args:
            connections_service: Connection Service
            connection_id: Connection ID

        Returns:
            ConnectionDetail
        """
        db_obj = await connections_service.get(connection_id)
        detail = connections_service.to_schema(db_obj, schema_type=ConnectionDetail)
        detail.credential_fields = _mask_credentials(db_obj)
        return detail

    @patch(
        operation_id="UpdateConnection",
        path="/api/connections/{connection_id:uuid}",
    )
    async def update_connection(
        self,
        data: ConnectionUpdate,
        connections_service: ConnectionService,
        connection_id: Annotated[UUID, Parameter(title="Connection ID", description="The connection to update.")],
    ) -> ConnectionDetail:
        """Update a connection.

        Args:
            data: Connection Update
            connections_service: Connection Service
            connection_id: Connection ID

        Returns:
            ConnectionDetail
        """
        await connections_service.update(
            item_id=connection_id,
            data=data.to_dict(),
        )
        db_obj = await connections_service.get_one(id=connection_id)
        detail = connections_service.to_schema(db_obj, schema_type=ConnectionDetail)
        detail.credential_fields = _mask_credentials(db_obj)
        return detail

    @delete(
        operation_id="DeleteConnection",
        path="/api/connections/{connection_id:uuid}",
    )
    async def delete_connection(
        self,
        connections_service: ConnectionService,
        connection_id: Annotated[UUID, Parameter(title="Connection ID", description="The connection to delete.")],
    ) -> None:
        """Delete a connection.

        Args:
            connections_service: Connection Service
            connection_id: Connection ID
        """
        _ = await connections_service.delete(connection_id)

    @post(
        operation_id="TestConnection",
        path="/api/connections/{connection_id:uuid}/test",
    )
    async def test_connection(
        self,
        connections_service: ConnectionService,
        connection_id: Annotated[UUID, Parameter(title="Connection ID", description="The connection to test.")],
    ) -> Message:
        """Test connectivity to an external data source.

        Args:
            connections_service: Connection Service
            connection_id: Connection ID

        Returns:
            Message
        """
        success, error_message = await connections_service.test_connection(connection_id)
        if success:
            return Message(message="Connection test successful.")
        return Message(message=f"Connection test failed: {error_message or 'Unknown error'}")
