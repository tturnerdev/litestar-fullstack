"""Webhooks domain schemas."""

from app.domain.webhooks.schemas._webhook import (
    WebhookCreate,
    WebhookDeliveryList,
    WebhookDetail,
    WebhookList,
    WebhookTestResult,
    WebhookUpdate,
)
from app.lib.schema import Message

__all__ = (
    "Message",
    "WebhookCreate",
    "WebhookDeliveryList",
    "WebhookDetail",
    "WebhookList",
    "WebhookTestResult",
    "WebhookUpdate",
)
