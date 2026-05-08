"""Webhooks domain schemas."""

from app.domain.webhooks.schemas._webhook import (
    WebhookCreate,
    WebhookDeliveryList,
    WebhookDetail,
    WebhookList,
    WebhookTestResult,
    WebhookUpdate,
)
from app.domain.webhooks.schemas._webhook_endpoint import (
    WebhookEndpoint,
    WebhookEndpointCreate,
    WebhookEndpointList,
    WebhookEndpointUpdate,
)
from app.domain.webhooks.schemas._webhook_event_type import WebhookEventTypeInfo
from app.lib.schema import Message

__all__ = (
    "Message",
    "WebhookCreate",
    "WebhookDeliveryList",
    "WebhookDetail",
    "WebhookEndpoint",
    "WebhookEndpointCreate",
    "WebhookEndpointList",
    "WebhookEndpointUpdate",
    "WebhookEventTypeInfo",
    "WebhookList",
    "WebhookTestResult",
    "WebhookUpdate",
)
