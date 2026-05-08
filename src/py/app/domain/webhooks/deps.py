"""Webhook domain dependencies."""

from __future__ import annotations

from app.domain.webhooks.services import WebhookDeliveryService, WebhookEndpointService, WebhookService
from app.lib.deps import create_service_provider

provide_webhooks_service = create_service_provider(
    WebhookService,
    error_messages={"duplicate_key": "This webhook already exists.", "integrity": "Webhook operation failed."},
)

provide_webhook_delivery_service = create_service_provider(
    WebhookDeliveryService,
    error_messages={"integrity": "Webhook delivery operation failed."},
)

provide_webhook_endpoint_service = create_service_provider(
    WebhookEndpointService,
    error_messages={"duplicate_key": "This webhook endpoint already exists.", "integrity": "Webhook endpoint operation failed."},
)

__all__ = ("provide_webhook_delivery_service", "provide_webhook_endpoint_service", "provide_webhooks_service")
