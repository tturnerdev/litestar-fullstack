"""Webhook domain dependencies."""

from __future__ import annotations

from app.domain.webhooks.services import WebhookService
from app.lib.deps import create_service_provider

provide_webhooks_service = create_service_provider(
    WebhookService,
    error_messages={"duplicate_key": "This webhook already exists.", "integrity": "Webhook operation failed."},
)

__all__ = ("provide_webhooks_service",)
