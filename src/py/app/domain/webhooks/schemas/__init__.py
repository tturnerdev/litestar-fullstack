"""Webhooks domain schemas."""

from app.domain.webhooks.schemas._webhook import (
    WebhookCreate,
    WebhookDetail,
    WebhookList,
    WebhookTestResult,
    WebhookUpdate,
)
from app.lib.schema import Message

__all__ = (
    "Message",
    "WebhookCreate",
    "WebhookDetail",
    "WebhookList",
    "WebhookTestResult",
    "WebhookUpdate",
)
