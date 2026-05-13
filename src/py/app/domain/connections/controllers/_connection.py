"""Connection Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, Request, delete, get, patch, post
from litestar.di import Provide
from litestar.exceptions import ClientException, PermissionDeniedException
from litestar.params import Dependency, Parameter
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.connections.guards import requires_connections_admin
from app.domain.connections.schemas import ConnectionCreate, ConnectionDetail, ConnectionList, ConnectionUpdate
from app.domain.connections.services import ConnectionService
from app.domain.teams.guards import requires_feature_permission
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies
from app.lib.schema import Message

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
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
        summary="List connections",
        description="Retrieve a paginated list of external service connections. Supports searching by name and optional filtering by team. Requires connections admin access.",
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
        return await connections_service.to_schema_enriched(results, total, filters, schema_type=ConnectionList)

    @post(
        operation_id="CreateConnection",
        summary="Create a connection",
        description="Register a new external service connection with its credentials. The user must belong to the target team. Records an audit log entry and emits a connection_created event.",
        path="/api/connections",
        guards=[requires_feature_permission("connections", "edit"), requires_connections_admin],
        status_code=HTTP_201_CREATED,
    )
    async def create_connection(
        self,
        request: Request[m.User, Token, Any],
        connections_service: ConnectionService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: ConnectionCreate,
    ) -> ConnectionDetail:
        """Create a new connection.

        Args:
            request: The current request
            connections_service: Connection Service
            audit_service: Audit Log Service
            current_user: Current User
            data: Connection Create

        Returns:
            ConnectionDetail
        """
        if not current_user.is_superuser and not any(tm.team_id == data.team_id for tm in current_user.teams):
            raise PermissionDeniedException(detail="You do not have access to this team")
        obj = data.to_dict()
        db_obj = await connections_service.create(obj)
        request.app.emit(event_id="connection_created", connection_id=db_obj.id)
        after = capture_snapshot(db_obj)
        result = await connections_service.to_schema_enriched(db_obj, schema_type=ConnectionDetail)
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
        return result

    @get(
        operation_id="GetConnection",
        summary="Get connection details",
        description="Retrieve details for a single connection. Credential values are never returned; only the credential field names are included.",
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
        detail = await connections_service.to_schema_enriched(db_obj, schema_type=ConnectionDetail)
        object.__setattr__(detail, "credential_fields", _mask_credentials(db_obj))
        return detail

    @patch(
        operation_id="UpdateConnection",
        summary="Update a connection",
        description="Update a connection's name, base URL, credentials, or enabled status. Records an audit log entry and emits a connection_updated event.",
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
        db_obj = await connections_service.update(
            item_id=connection_id,
            data=data.to_dict(),
        )
        request.app.emit(event_id="connection_updated", connection_id=db_obj.id)
        after = capture_snapshot(db_obj)
        detail = await connections_service.to_schema_enriched(db_obj, schema_type=ConnectionDetail)
        object.__setattr__(detail, "credential_fields", _mask_credentials(db_obj))
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
        return detail

    @delete(
        operation_id="DeleteConnection",
        summary="Delete a connection",
        description="Delete an external service connection. Fails with HTTP 409 if devices are still managed through this connection. Records an audit log entry.",
        path="/api/connections/{connection_id:uuid}",
        guards=[requires_feature_permission("connections", "edit"), requires_connections_admin],
        status_code=HTTP_204_NO_CONTENT,
        return_dto=None,
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
        device_count = await connections_service.get_device_count(connection_id)
        if device_count > 0:
            raise ClientException(
                detail=f"Cannot delete connection with {device_count} managed device(s). Reassign devices first.",
                status_code=409,
            )
        before = capture_snapshot(db_obj)
        target_label = db_obj.name
        request.app.emit(event_id="connection_deleted", connection_id=connection_id)
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
        summary="Test a connection",
        description="Test connectivity to the external service by attempting to authenticate with the stored credentials. Returns a success or failure message.",
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
