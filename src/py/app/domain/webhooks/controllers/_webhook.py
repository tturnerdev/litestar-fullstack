"""Webhook Controllers."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

import httpx
from litestar import Controller, Request, delete, get, patch, post
from litestar.di import Provide
from litestar.exceptions import NotFoundException
from litestar.params import Dependency, Parameter
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT

from app.db import models as m
from app.domain.accounts.guards import requires_superuser
from app.domain.admin.deps import provide_audit_log_service
from app.domain.webhooks.deps import provide_webhook_delivery_service
from app.domain.webhooks.schemas import (
    WebhookCreate,
    WebhookDeliveryDetail,
    WebhookDeliveryList,
    WebhookDetail,
    WebhookList,
    WebhookTestResult,
    WebhookUpdate,
)
from app.domain.webhooks.services import WebhookDeliveryService, WebhookService, redeliver
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService

_SECRET_VISIBLE_CHARS = 4


def _mask_secret(secret: str | None) -> str | None:
    """Mask webhook secret, showing only the last few characters."""
    if not secret:
        return None
    if len(secret) <= _SECRET_VISIBLE_CHARS:
        return "*" * len(secret)
    return "*" * (len(secret) - _SECRET_VISIBLE_CHARS) + secret[-_SECRET_VISIBLE_CHARS:]


def _to_detail(service: WebhookService, obj: m.Webhook) -> WebhookDetail:
    """Convert a Webhook model to a WebhookDetail schema with masked secret."""
    detail = service.to_schema(obj, schema_type=WebhookDetail)
    object.__setattr__(detail, "secret", _mask_secret(obj.secret))
    return detail


class WebhookController(Controller):
    """Webhooks."""

    tags = ["Webhooks"]
    guards = [requires_superuser]
    dependencies = create_service_dependencies(
        WebhookService,
        key="webhooks_service",
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
        "delivery_service": Provide(provide_webhook_delivery_service),
    }

    @get(
        operation_id="ListWebhooks",
        summary="List webhooks",
        description="Retrieve a paginated list of webhooks owned by the current user. Supports search by name, date range filtering, and sorting.",
        path="/api/webhooks",
    )
    async def list_webhooks(
        self,
        webhooks_service: WebhookService,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[WebhookList]:
        """List all webhooks.

        Args:
            webhooks_service: Webhook Service
            filters: Filters

        Returns:
            OffsetPagination[WebhookList]
        """
        results, total = await webhooks_service.list_and_count(*filters)
        return webhooks_service.to_schema(results, total, filters, schema_type=WebhookList)

    @post(
        operation_id="CreateWebhook",
        summary="Create a webhook",
        description="Register a new webhook for the current user. Emits a webhook_created event and logs an audit entry.",
        path="/api/webhooks",
        status_code=HTTP_201_CREATED,
    )
    async def create_webhook(
        self,
        request: Request[m.User, Token, Any],
        webhooks_service: WebhookService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: WebhookCreate,
    ) -> WebhookDetail:
        """Create a new webhook.

        Args:
            request: The current request
            webhooks_service: Webhook Service
            audit_service: Audit Log Service
            current_user: Current User
            data: Webhook Create

        Returns:
            WebhookDetail
        """
        obj = data.to_dict()
        obj["user_id"] = current_user.id
        db_obj = await webhooks_service.create(obj)
        request.app.emit(event_id="webhook_created", webhook_id=db_obj.id)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="webhook.created",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="webhook",
            target_id=db_obj.id,
            target_label=db_obj.name,
            before=None,
            after=after,
            request=request,
        )
        return _to_detail(webhooks_service, db_obj)

    @get(
        operation_id="GetWebhook",
        summary="Get webhook details",
        description="Retrieve a single webhook by ID with its secret masked. Superusers may access any webhook; regular users may only access their own.",
        path="/api/webhooks/{webhook_id:uuid}",
    )
    async def get_webhook(
        self,
        webhooks_service: WebhookService,
        webhook_id: Annotated[UUID, Parameter(title="Webhook ID", description="The webhook to retrieve.")],
    ) -> WebhookDetail:
        """Get details about a webhook.

        Args:
            webhooks_service: Webhook Service
            webhook_id: Webhook ID

        Returns:
            WebhookDetail
        """
        db_obj = await webhooks_service.get(webhook_id)
        return _to_detail(webhooks_service, db_obj)

    @patch(
        operation_id="UpdateWebhook",
        summary="Update a webhook",
        description="Partially update a webhook's configuration. Emits a webhook_updated event and logs an audit entry with before/after snapshots.",
        path="/api/webhooks/{webhook_id:uuid}",
    )
    async def update_webhook(
        self,
        request: Request[m.User, Token, Any],
        data: WebhookUpdate,
        webhooks_service: WebhookService,
        audit_service: AuditLogService,
        current_user: m.User,
        webhook_id: Annotated[UUID, Parameter(title="Webhook ID", description="The webhook to update.")],
    ) -> WebhookDetail:
        """Update a webhook.

        Args:
            request: The current request
            data: Webhook Update
            webhooks_service: Webhook Service
            audit_service: Audit Log Service
            current_user: Current User
            webhook_id: Webhook ID

        Returns:
            WebhookDetail
        """
        existing = await webhooks_service.get(webhook_id)
        before = capture_snapshot(existing)
        fresh_obj = await webhooks_service.update(
            item_id=webhook_id,
            data=data.to_dict(),
        )
        request.app.emit(event_id="webhook_updated", webhook_id=fresh_obj.id)
        after = capture_snapshot(fresh_obj)
        await log_audit(
            audit_service,
            action="webhook.updated",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="webhook",
            target_id=webhook_id,
            target_label=fresh_obj.name,
            before=before,
            after=after,
            request=request,
        )
        return _to_detail(webhooks_service, fresh_obj)

    @delete(
        operation_id="DeleteWebhook",
        summary="Delete a webhook",
        description="Permanently delete a webhook and its configuration. Emits a webhook_deleted event and logs an audit entry with the before-state snapshot.",
        path="/api/webhooks/{webhook_id:uuid}",
        status_code=HTTP_204_NO_CONTENT,
        return_dto=None,
    )
    async def delete_webhook(
        self,
        request: Request[m.User, Token, Any],
        webhooks_service: WebhookService,
        audit_service: AuditLogService,
        current_user: m.User,
        webhook_id: Annotated[UUID, Parameter(title="Webhook ID", description="The webhook to delete.")],
    ) -> None:
        """Delete a webhook.

        Args:
            request: The current request
            webhooks_service: Webhook Service
            audit_service: Audit Log Service
            current_user: Current User
            webhook_id: Webhook ID
        """
        db_obj = await webhooks_service.get(webhook_id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.name
        request.app.emit(event_id="webhook_deleted", webhook_id=webhook_id)
        await webhooks_service.delete(webhook_id)
        await log_audit(
            audit_service,
            action="webhook.deleted",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="webhook",
            target_id=webhook_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )

    @get(
        operation_id="ListWebhookDeliveries",
        summary="List webhook deliveries",
        description="Retrieve the 20 most recent delivery attempts for a specific webhook, ordered by most recent first.",
        path="/api/webhooks/{webhook_id:uuid}/deliveries",
    )
    async def list_deliveries(
        self,
        webhooks_service: WebhookService,
        delivery_service: WebhookDeliveryService,
        webhook_id: Annotated[UUID, Parameter(title="Webhook ID", description="The webhook to list deliveries for.")],
    ) -> list[WebhookDeliveryList]:
        """List the 20 most recent deliveries for a webhook.

        Args:
            webhooks_service: Webhook Service
            delivery_service: Webhook Delivery Service
            webhook_id: Webhook ID

        Returns:
            list[WebhookDeliveryList]
        """
        await webhooks_service.get(webhook_id)

        from advanced_alchemy.filters import LimitOffset, OrderBy

        results, _total = await delivery_service.list_and_count(
            m.WebhookDelivery.webhook_id == webhook_id,
            LimitOffset(limit=20, offset=0),
            OrderBy(field_name="created_at", sort_order="desc"),
        )
        return delivery_service.to_schema(results, schema_type=WebhookDeliveryList)

    @post(
        operation_id="RedeliverWebhookDelivery",
        summary="Redeliver a webhook",
        description="Manually retry a previous webhook delivery attempt. Re-sends the original payload to the webhook URL and records the new delivery result.",
        path="/api/webhooks/{webhook_id:uuid}/deliveries/{delivery_id:uuid}/redeliver",
    )
    async def redeliver_delivery(
        self,
        webhooks_service: WebhookService,
        delivery_service: WebhookDeliveryService,
        webhook_id: Annotated[UUID, Parameter(title="Webhook ID", description="The webhook that owns the delivery.")],
        delivery_id: Annotated[UUID, Parameter(title="Delivery ID", description="The delivery to redeliver.")],
    ) -> WebhookDeliveryDetail:
        """Manually redeliver a failed webhook delivery.

        Args:
            webhooks_service: Webhook Service
            delivery_service: Webhook Delivery Service
            webhook_id: Webhook ID
            delivery_id: Delivery ID

        Returns:
            WebhookDeliveryDetail
        """
        await webhooks_service.get(webhook_id)

        delivery = await delivery_service.get(delivery_id)
        if delivery.webhook_id != webhook_id:
            raise NotFoundException(detail="Delivery not found.")

        await redeliver(delivery, delivery_service)
        updated = await delivery_service.get(delivery_id)
        return delivery_service.to_schema(updated, schema_type=WebhookDeliveryDetail)

    @post(
        operation_id="TestWebhook",
        summary="Send a test webhook",
        description="Send a test payload to the webhook URL and return the result including status code, response time, and any errors. Records the delivery attempt.",
        path="/api/webhooks/{webhook_id:uuid}/test",
    )
    async def test_webhook(
        self,
        webhooks_service: WebhookService,
        delivery_service: WebhookDeliveryService,
        webhook_id: Annotated[UUID, Parameter(title="Webhook ID", description="The webhook to test.")],
    ) -> WebhookTestResult:
        """Send a test payload to a webhook URL and return the result.

        Args:
            webhooks_service: Webhook Service
            delivery_service: Webhook Delivery Service
            webhook_id: Webhook ID

        Returns:
            WebhookTestResult
        """
        db_obj = await webhooks_service.get(webhook_id)

        test_payload = {
            "event": "webhook.test",
            "webhook_id": str(db_obj.id),
            "timestamp": time.time(),
            "data": {
                "message": "This is a test webhook delivery.",
            },
        }

        custom_headers = dict(db_obj.headers) if db_obj.headers else {}
        custom_headers["Content-Type"] = "application/json"
        custom_headers["X-Webhook-Event"] = "webhook.test"

        if db_obj.secret:
            custom_headers["X-Webhook-Secret"] = db_obj.secret

        status_code: int | None = None
        elapsed_ms: int = 0
        success: bool = False
        error: str | None = None

        start_time = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    db_obj.url,
                    json=test_payload,
                    headers=custom_headers,
                )
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            status_code = response.status_code
            success = 200 <= response.status_code < 300
            if not success:
                error = f"HTTP {response.status_code}"
        except httpx.TimeoutException:
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            error = "Request timed out after 10 seconds"
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            error = str(exc)

        # Record the delivery attempt
        await delivery_service.create(
            {
                "webhook_id": webhook_id,
                "event": "webhook.test",
                "status_code": status_code,
                "response_time_ms": elapsed_ms,
                "success": success,
                "error": error,
            }
        )

        return WebhookTestResult(
            success=success,
            status_code=status_code,
            response_time_ms=elapsed_ms,
            error=error,
        )
