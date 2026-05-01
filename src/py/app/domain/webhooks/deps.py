"""Webhook domain dependencies."""

from __future__ import annotations

from app.domain.webhooks.services import WebhookDeliveryService, WebhookService
from app.lib.deps import create_service_provider

provide_webhooks_service = create_service_provider(
    WebhookService,
    error_messages={"duplicate_key": "This webhook already exists.", "integrity": "Webhook operation failed."},
)

provide_webhook_delivery_service = create_service_provider(
    WebhookDeliveryService,
    error_messages={"integrity": "Webhook delivery operation failed."},
)

__all__ = ("provide_webhook_delivery_service", "provide_webhooks_service")
