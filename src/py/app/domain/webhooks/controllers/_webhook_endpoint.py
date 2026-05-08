"""Webhook Endpoint Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, Request, delete, get, patch, post
from litestar.datastructures import CacheControlHeader
from litestar.params import Dependency, Parameter
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT

from app.domain.accounts.guards import requires_superuser
from app.domain.webhooks.events import get_all_event_types
from app.domain.webhooks.schemas import (
    WebhookEndpoint,
    WebhookEndpointCreate,
    WebhookEndpointList,
    WebhookEndpointUpdate,
    WebhookEventTypeInfo,
)
from app.domain.webhooks.services import WebhookEndpointService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination


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
    )

    @get(operation_id="ListWebhookEndpoints", summary="List webhook endpoints")
    async def list_endpoints(
        self,
        webhook_service: WebhookEndpointService,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[WebhookEndpointList]:
        results, total = await webhook_service.list_and_count(*filters)
        return webhook_service.to_schema(results, total, filters, schema_type=WebhookEndpointList)

    @get(operation_id="GetWebhookEndpoint", summary="Get webhook endpoint details", path="/{endpoint_id:uuid}")
    async def get_endpoint(
        self,
        webhook_service: WebhookEndpointService,
        endpoint_id: Annotated[UUID, Parameter(title="Endpoint ID")],
    ) -> WebhookEndpoint:
        db_obj = await webhook_service.get(endpoint_id)
        return webhook_service.to_schema(db_obj, schema_type=WebhookEndpoint)

    @post(operation_id="CreateWebhookEndpoint", summary="Create a webhook endpoint", status_code=HTTP_201_CREATED)
    async def create_endpoint(
        self,
        request: Request[Any, Any, Any],
        webhook_service: WebhookEndpointService,
        data: WebhookEndpointCreate,
    ) -> WebhookEndpoint:
        db_obj = await webhook_service.create(data.to_dict())
        request.app.emit(event_id="webhook_endpoint_created", entity_id=db_obj.id)
        return webhook_service.to_schema(db_obj, schema_type=WebhookEndpoint)

    @patch(operation_id="UpdateWebhookEndpoint", summary="Update a webhook endpoint", path="/{endpoint_id:uuid}")
    async def update_endpoint(
        self,
        request: Request[Any, Any, Any],
        webhook_service: WebhookEndpointService,
        data: WebhookEndpointUpdate,
        endpoint_id: Annotated[UUID, Parameter(title="Endpoint ID")],
    ) -> WebhookEndpoint:
        db_obj = await webhook_service.update(item_id=endpoint_id, data=data.to_dict())
        request.app.emit(event_id="webhook_endpoint_updated", entity_id=db_obj.id)
        return webhook_service.to_schema(db_obj, schema_type=WebhookEndpoint)

    @delete(operation_id="DeleteWebhookEndpoint", summary="Delete a webhook endpoint", path="/{endpoint_id:uuid}", return_dto=None, status_code=HTTP_204_NO_CONTENT)
    async def delete_endpoint(
        self,
        request: Request[Any, Any, Any],
        webhook_service: WebhookEndpointService,
        endpoint_id: Annotated[UUID, Parameter(title="Endpoint ID")],
    ) -> None:
        request.app.emit(event_id="webhook_endpoint_deleted", entity_id=endpoint_id)
        _ = await webhook_service.delete(endpoint_id)

    @get(
        operation_id="ListWebhookEventTypes",
        summary="List webhook event types",
        path="/event-types",
        cache=300,
        cache_control=CacheControlHeader(private=True, max_age=300),
    )
    async def list_event_types(self) -> list[WebhookEventTypeInfo]:
        event_types = get_all_event_types()
        return [WebhookEventTypeInfo(event=et["event"], description=et["description"]) for et in event_types]
