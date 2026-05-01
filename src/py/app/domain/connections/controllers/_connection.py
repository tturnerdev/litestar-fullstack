"""Connection Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Dependency, Parameter

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.connections.guards import requires_connections_admin
from app.domain.connections.schemas import ConnectionCreate, ConnectionDetail, ConnectionList, ConnectionUpdate
from app.domain.teams.guards import requires_feature_permission
from app.domain.connections.services import ConnectionService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies
from app.lib.schema import Message

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


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
    ) | {
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(
        operation_id="ListConnections",
        path="/api/connections",
        guards=[requires_feature_permission("connections", "view"), requires_connections_admin],
    )
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

    @post(
        operation_id="CreateConnection",
        path="/api/connections",
        guards=[requires_feature_permission("connections", "edit"), requires_connections_admin],
    )
    async def create_connection(
        self,
        request: Request[m.User, Token, Any],
        connections_service: ConnectionService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: ConnectionCreate,
    ) -> ConnectionList:
        """Create a new connection.

        Args:
            request: The current request
            connections_service: Connection Service
            audit_service: Audit Log Service
            current_user: Current User
            data: Connection Create

        Returns:
            ConnectionList
        """
        obj = data.to_dict()
        db_obj = await connections_service.create(obj)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="connection.created",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="connection",
            target_id=db_obj.id,
            target_label=db_obj.name,
            before=None,
            after=after,
            request=request,
        )
        return connections_service.to_schema(db_obj, schema_type=ConnectionList)

    @get(
        operation_id="GetConnection",
        path="/api/connections/{connection_id:uuid}",
        guards=[requires_feature_permission("connections", "view"), requires_connections_admin],
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
        guards=[requires_feature_permission("connections", "edit"), requires_connections_admin],
    )
    async def update_connection(
        self,
        request: Request[m.User, Token, Any],
        data: ConnectionUpdate,
        connections_service: ConnectionService,
        audit_service: AuditLogService,
        current_user: m.User,
        connection_id: Annotated[UUID, Parameter(title="Connection ID", description="The connection to update.")],
    ) -> ConnectionDetail:
        """Update a connection.

        Args:
            request: The current request
            data: Connection Update
            connections_service: Connection Service
            audit_service: Audit Log Service
            current_user: Current User
            connection_id: Connection ID

        Returns:
            ConnectionDetail
        """
        before = capture_snapshot(await connections_service.get(connection_id))
        await connections_service.update(
            item_id=connection_id,
            data=data.to_dict(),
        )
        db_obj = await connections_service.get_one(id=connection_id)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="connection.updated",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="connection",
            target_id=connection_id,
            target_label=db_obj.name,
            before=before,
            after=after,
            request=request,
        )
        detail = connections_service.to_schema(db_obj, schema_type=ConnectionDetail)
        detail.credential_fields = _mask_credentials(db_obj)
        return detail

    @delete(
        operation_id="DeleteConnection",
        path="/api/connections/{connection_id:uuid}",
        guards=[requires_feature_permission("connections", "edit"), requires_connections_admin],
    )
    async def delete_connection(
        self,
        request: Request[m.User, Token, Any],
        connections_service: ConnectionService,
        audit_service: AuditLogService,
        current_user: m.User,
        connection_id: Annotated[UUID, Parameter(title="Connection ID", description="The connection to delete.")],
    ) -> None:
        """Delete a connection.

        Args:
            request: The current request
            connections_service: Connection Service
            audit_service: Audit Log Service
            current_user: Current User
            connection_id: Connection ID
        """
        db_obj = await connections_service.get(connection_id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.name
        await connections_service.delete(connection_id)
        await log_audit(
            audit_service,
            action="connection.deleted",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="connection",
            target_id=connection_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )

    @post(
        operation_id="TestConnection",
        path="/api/connections/{connection_id:uuid}/test",
        guards=[requires_feature_permission("connections", "edit"), requires_connections_admin],
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
