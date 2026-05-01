"""Webhook Controllers."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

import httpx
from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.exceptions import NotFoundException
from litestar.params import Dependency, Parameter

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.webhooks.schemas import WebhookCreate, WebhookDetail, WebhookList, WebhookTestResult, WebhookUpdate
from app.domain.webhooks.services import WebhookService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


def _mask_secret(secret: str | None) -> str | None:
    """Mask webhook secret, showing only the last 4 characters."""
    if not secret:
        return None
    if len(secret) <= 4:
        return "*" * len(secret)
    return "*" * (len(secret) - 4) + secret[-4:]


def _to_detail(service: WebhookService, obj: m.Webhook) -> WebhookDetail:
    """Convert a Webhook model to a WebhookDetail schema with masked secret."""
    detail = service.to_schema(obj, schema_type=WebhookDetail)
    return WebhookDetail(
        id=detail.id,
        name=detail.name,
        url=detail.url,
        secret=_mask_secret(obj.secret),
        events=detail.events,
        is_active=detail.is_active,
        headers=detail.headers,
        description=detail.description,
        last_triggered_at=detail.last_triggered_at,
        last_status_code=detail.last_status_code,
        failure_count=detail.failure_count,
        user_id=detail.user_id,
        created_at=detail.created_at,
        updated_at=detail.updated_at,
    )


class WebhookController(Controller):
    """Webhooks."""

    tags = ["Webhooks"]
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
    }

    @get(operation_id="ListWebhooks", path="/api/webhooks")
    async def list_webhooks(
        self,
        webhooks_service: WebhookService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[WebhookList]:
        """List webhooks for the current user.

        Args:
            webhooks_service: Webhook Service
            current_user: Current User
            filters: Filters

        Returns:
            OffsetPagination[WebhookList]
        """
        results, total = await webhooks_service.list_and_count(
            *filters,
            m.Webhook.user_id == current_user.id,
        )
        return webhooks_service.to_schema(results, total, filters, schema_type=WebhookList)

    @post(operation_id="CreateWebhook", path="/api/webhooks")
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
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="webhook.create",
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
        path="/api/webhooks/{webhook_id:uuid}",
    )
    async def get_webhook(
        self,
        webhooks_service: WebhookService,
        current_user: m.User,
        webhook_id: Annotated[UUID, Parameter(title="Webhook ID", description="The webhook to retrieve.")],
    ) -> WebhookDetail:
        """Get details about a webhook.

        Args:
            webhooks_service: Webhook Service
            current_user: Current User
            webhook_id: Webhook ID

        Returns:
            WebhookDetail
        """
        db_obj = await webhooks_service.get(webhook_id)
        if db_obj.user_id != current_user.id and not current_user.is_superuser:
            raise NotFoundException(detail="Webhook not found.")
        return _to_detail(webhooks_service, db_obj)

    @patch(
        operation_id="UpdateWebhook",
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
        if existing.user_id != current_user.id and not current_user.is_superuser:
            raise NotFoundException(detail="Webhook not found.")
        before = capture_snapshot(existing)
        await webhooks_service.update(
            item_id=webhook_id,
            data=data.to_dict(),
        )
        fresh_obj = await webhooks_service.get_one(id=webhook_id)
        after = capture_snapshot(fresh_obj)
        await log_audit(
            audit_service,
            action="webhook.update",
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
        path="/api/webhooks/{webhook_id:uuid}",
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
        if db_obj.user_id != current_user.id and not current_user.is_superuser:
            raise NotFoundException(detail="Webhook not found.")
        before = capture_snapshot(db_obj)
        target_label = db_obj.name
        await webhooks_service.delete(webhook_id)
        await log_audit(
            audit_service,
            action="webhook.delete",
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

    @post(
        operation_id="TestWebhook",
        path="/api/webhooks/{webhook_id:uuid}/test",
    )
    async def test_webhook(
        self,
        webhooks_service: WebhookService,
        current_user: m.User,
        webhook_id: Annotated[UUID, Parameter(title="Webhook ID", description="The webhook to test.")],
    ) -> WebhookTestResult:
        """Send a test payload to a webhook URL and return the result.

        Args:
            webhooks_service: Webhook Service
            current_user: Current User
            webhook_id: Webhook ID

        Returns:
            WebhookTestResult
        """
        db_obj = await webhooks_service.get(webhook_id)
        if db_obj.user_id != current_user.id and not current_user.is_superuser:
            raise NotFoundException(detail="Webhook not found.")

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

        start_time = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    db_obj.url,
                    json=test_payload,
                    headers=custom_headers,
                )
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            success = 200 <= response.status_code < 300
            return WebhookTestResult(
                success=success,
                status_code=response.status_code,
                response_time_ms=elapsed_ms,
                error=None if success else f"HTTP {response.status_code}",
            )
        except httpx.TimeoutException:
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            return WebhookTestResult(
                success=False,
                status_code=None,
                response_time_ms=elapsed_ms,
                error="Request timed out after 10 seconds",
            )
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            return WebhookTestResult(
                success=False,
                status_code=None,
                response_time_ms=elapsed_ms,
                error=str(exc),
            )
