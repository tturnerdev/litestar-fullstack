"""Webhook dispatcher — sends HTTP POST requests to registered endpoints."""

from __future__ import annotations

import hashlib
import hmac
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import httpx
import structlog

if TYPE_CHECKING:
    from app.db import models as m
    from app.domain.webhooks.services._webhook_delivery import WebhookDeliveryService
    from app.domain.webhooks.services._webhook_endpoint import WebhookEndpointService

logger = structlog.get_logger()

WEBHOOK_TIMEOUT_SECONDS = 10
WEBHOOK_MAX_RESPONSE_BODY_LENGTH = 1024


def _compute_signature(payload_bytes: bytes, secret: str) -> str:
    """Compute HMAC-SHA256 signature for webhook payload.

    Args:
        payload_bytes: The raw JSON payload bytes.
        secret: The shared secret.

    Returns:
        Hex-encoded HMAC-SHA256 signature prefixed with 'sha256='.
    """
    mac = hmac.new(secret.encode(), payload_bytes, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


async def dispatch_webhook_event(
    event_type: str,
    payload: dict[str, Any],
    endpoint_service: WebhookEndpointService,
    delivery_service: WebhookDeliveryService | None = None,
) -> None:
    """Dispatch a webhook event to all subscribed endpoints."""
    endpoints = await endpoint_service.get_active_endpoints_for_event(event_type)

    if not endpoints:
        await logger.adebug("No webhook endpoints for event", event_type=event_type)
        return

    await logger.ainfo(
        "Dispatching webhook event",
        event_type=event_type,
        endpoint_count=len(endpoints),
    )

    for endpoint in endpoints:
        await _deliver_to_endpoint(
            endpoint=endpoint,
            event_type=event_type,
            payload=payload,
        )


async def _deliver_to_endpoint(
    endpoint: m.WebhookEndpoint,
    event_type: str,
    payload: dict[str, Any],
) -> None:
    """Send a webhook payload to a single endpoint."""
    import msgspec

    full_payload = {
        "event": event_type,
        "timestamp": datetime.now(UTC).isoformat(),
        "data": payload,
    }

    payload_bytes = msgspec.json.encode(full_payload)

    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "User-Agent": "AdminPortal-Webhook/1.0",
        "X-Webhook-Event": event_type,
    }

    if endpoint.secret:
        headers["X-Webhook-Signature"] = _compute_signature(payload_bytes, endpoint.secret)

    if endpoint.headers:
        headers.update(endpoint.headers)

    start_time = time.monotonic()

    try:
        async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT_SECONDS) as client:
            response = await client.post(
                endpoint.url,
                content=payload_bytes,
                headers=headers,
            )
            duration_ms = int((time.monotonic() - start_time) * 1000)
            status = "success" if 200 <= response.status_code < 300 else "failed"

            log_method = logger.ainfo if status == "success" else logger.awarning
            await log_method(
                "Webhook delivery completed",
                endpoint_id=str(endpoint.id),
                event_type=event_type,
                status=status,
                duration_ms=duration_ms,
                response_status=response.status_code,
            )

    except httpx.TimeoutException:
        await logger.awarning("Webhook delivery timed out", endpoint_id=str(endpoint.id), event_type=event_type)
    except httpx.RequestError as exc:
        await logger.awarning("Webhook delivery failed", endpoint_id=str(endpoint.id), event_type=event_type, error=str(exc))
    except Exception:
        await logger.aexception("Webhook delivery failed unexpectedly", endpoint_id=str(endpoint.id))
