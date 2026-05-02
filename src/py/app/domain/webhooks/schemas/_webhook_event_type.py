"""Webhook event type schema."""

from app.lib.schema import CamelizedBaseStruct


class WebhookEventTypeInfo(CamelizedBaseStruct):
    """Available webhook event type information."""

    event: str
    description: str
