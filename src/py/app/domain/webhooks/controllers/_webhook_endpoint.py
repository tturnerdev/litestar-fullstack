"""Webhook Endpoint Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, Request, delete, get, patch, post
from litestar.datastructures import CacheControlHeader
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT

from app.db import models as m
from app.domain.accounts.guards import requires_superuser
from app.domain.admin.deps import provide_audit_log_service
from app.domain.webhooks.events import get_all_event_types
from app.domain.webhooks.schemas import (
    WebhookEndpoint,
    WebhookEndpointCreate,
    WebhookEndpointList,
    WebhookEndpointUpdate,
    WebhookEventTypeInfo,
)
from app.domain.webhooks.services import WebhookEndpointService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class WebhookEndpointController(Controller):
    tags = ["Webhook Endpoints"]
    path = "/api/webhooks/endpoints"
    guards = [requires_superuser]
    dependencies = create_service_dependencies(
        WebhookEndpointService,
        key="webhook_service",
        filters={
            "id_filter": UUID,
            "search": "url,description",
            "pagination_type": "limit_offset",
            "pagination_size": 25,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    ) | {
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(
        operation_id="ListWebhookEndpoints",
        summary="List webhook endpoints",
        description="Retrieve a paginated list of system-level webhook endpoints. Supports search by URL and description, date range filtering, and sorting.",
    )
    async def list_endpoints(
        self,
        webhook_service: WebhookEndpointService,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[WebhookEndpointList]:
        results, total = await webhook_service.list_and_count(*filters)
        return webhook_service.to_schema(results, total, filters, schema_type=WebhookEndpointList)

    @get(
        operation_id="GetWebhookEndpoint",
        summary="Get webhook endpoint details",
        description="Retrieve a single webhook endpoint by ID, including its subscribed event types and configuration.",
        path="/{endpoint_id:uuid}",
    )
    async def get_endpoint(
        self,
        webhook_service: WebhookEndpointService,
        endpoint_id: Annotated[UUID, Parameter(title="Endpoint ID")],
    ) -> WebhookEndpoint:
        db_obj = await webhook_service.get(endpoint_id)
        return webhook_service.to_schema(db_obj, schema_type=WebhookEndpoint)

    @post(
        operation_id="CreateWebhookEndpoint",
        summary="Create a webhook endpoint",
        description="Register a new system-level webhook endpoint. Emits a webhook_endpoint_created event and logs an audit entry.",
        status_code=HTTP_201_CREATED,
    )
    async def create_endpoint(
        self,
        request: Request[m.User, Token, Any],
        webhook_service: WebhookEndpointService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: WebhookEndpointCreate,
    ) -> WebhookEndpoint:
        db_obj = await webhook_service.create(data.to_dict())
        request.app.emit(event_id="webhook_endpoint_created", endpoint_id=db_obj.id)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="webhook.endpoint.created",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="webhook_endpoint",
            target_id=db_obj.id,
            target_label=db_obj.url,
            before=None,
            after=after,
            request=request,
        )
        return webhook_service.to_schema(db_obj, schema_type=WebhookEndpoint)

    @patch(
        operation_id="UpdateWebhookEndpoint",
        summary="Update a webhook endpoint",
        description="Partially update a webhook endpoint's URL, event subscriptions, or other settings. Emits a webhook_endpoint_updated event and logs an audit entry with before/after snapshots.",
        path="/{endpoint_id:uuid}",
    )
    async def update_endpoint(
        self,
        request: Request[m.User, Token, Any],
        webhook_service: WebhookEndpointService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: WebhookEndpointUpdate,
        endpoint_id: Annotated[UUID, Parameter(title="Endpoint ID")],
    ) -> WebhookEndpoint:
        existing = await webhook_service.get(endpoint_id)
        before = capture_snapshot(existing)
        db_obj = await webhook_service.update(item_id=endpoint_id, data=data.to_dict())
        request.app.emit(event_id="webhook_endpoint_updated", endpoint_id=db_obj.id)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="webhook.endpoint.updated",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="webhook_endpoint",
            target_id=endpoint_id,
            target_label=db_obj.url,
            before=before,
            after=after,
            request=request,
        )
        return webhook_service.to_schema(db_obj, schema_type=WebhookEndpoint)

    @delete(
        operation_id="DeleteWebhookEndpoint",
        summary="Delete a webhook endpoint",
        description="Permanently delete a webhook endpoint. Emits a webhook_endpoint_deleted event and logs an audit entry with the before-state snapshot.",
        path="/{endpoint_id:uuid}",
        return_dto=None,
        status_code=HTTP_204_NO_CONTENT,
    )
    async def delete_endpoint(
        self,
        request: Request[m.User, Token, Any],
        webhook_service: WebhookEndpointService,
        audit_service: AuditLogService,
        current_user: m.User,
        endpoint_id: Annotated[UUID, Parameter(title="Endpoint ID")],
    ) -> None:
        db_obj = await webhook_service.get(endpoint_id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.url
        request.app.emit(event_id="webhook_endpoint_deleted", endpoint_id=endpoint_id)
        _ = await webhook_service.delete(endpoint_id)
        await log_audit(
            audit_service,
            action="webhook.endpoint.deleted",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="webhook_endpoint",
            target_id=endpoint_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )

    @get(
        operation_id="ListWebhookEventTypes",
        summary="List webhook event types",
        description="Return all registered webhook event types with their descriptions. Response is cached for 5 minutes.",
        path="/event-types",
        cache=300,
        cache_control=CacheControlHeader(private=True, max_age=300),
    )
    async def list_event_types(self) -> list[WebhookEventTypeInfo]:
        event_types = get_all_event_types()
        return [WebhookEventTypeInfo(event=et["event"], description=et["description"]) for et in event_types]
