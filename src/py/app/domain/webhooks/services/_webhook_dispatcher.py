"""Webhook dispatcher — sends HTTP POST requests to registered endpoints."""

from __future__ import annotations

import hashlib
import hmac
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import httpx
import structlog

if TYPE_CHECKING:
    from uuid import UUID

    from app.db import models as m
    from app.domain.webhooks.services._webhook_delivery import WebhookDeliveryService
    from app.domain.webhooks.services._webhook_endpoint import WebhookEndpointService

logger = structlog.get_logger()

WEBHOOK_TIMEOUT_SECONDS = 10
WEBHOOK_MAX_RESPONSE_BODY_LENGTH = 1024

# Exponential backoff intervals in seconds: 30s, 2m, 8m, 32m, 2h
RETRY_BACKOFF_SECONDS = [30, 120, 480, 1920, 7200]


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


def _compute_next_retry_at(retry_count: int) -> datetime | None:
    """Compute the next retry timestamp using exponential backoff.

    Args:
        retry_count: The current retry count (0-based, before incrementing).

    Returns:
        The datetime for the next retry, or None if max retries exceeded.
    """
    if retry_count >= len(RETRY_BACKOFF_SECONDS):
        return None
    delay = RETRY_BACKOFF_SECONDS[retry_count]
    return datetime.now(UTC) + timedelta(seconds=delay)


async def dispatch_webhook_event(
    event_type: str,
    payload: dict[str, Any],
    endpoint_service: WebhookEndpointService,
    delivery_service: WebhookDeliveryService | None = None,
    *,
    webhook_id: UUID | None = None,
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
            delivery_service=delivery_service,
            webhook_id=webhook_id,
        )


async def _deliver_to_endpoint(
    endpoint: m.WebhookEndpoint,
    event_type: str,
    payload: dict[str, Any],
    delivery_service: WebhookDeliveryService | None = None,
    webhook_id: UUID | None = None,
) -> None:
    """Send a webhook payload to a single endpoint and record the delivery."""
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
    status_code: int | None = None
    success = False
    error_msg: str | None = None

    try:
        async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT_SECONDS) as client:
            response = await client.post(
                endpoint.url,
                content=payload_bytes,
                headers=headers,
            )
            status_code = response.status_code
            success = response.is_success

            if not success:
                error_msg = response.text[:WEBHOOK_MAX_RESPONSE_BODY_LENGTH] if response.text else None

    except httpx.TimeoutException:
        error_msg = "Request timed out"
    except httpx.RequestError as exc:
        error_msg = str(exc)
    except Exception as exc:  # noqa: BLE001
        error_msg = f"Unexpected error: {exc}"

    duration_ms = int((time.monotonic() - start_time) * 1000)

    log_method = logger.ainfo if success else logger.awarning
    await log_method(
        "Webhook delivery completed",
        endpoint_id=str(endpoint.id),
        event_type=event_type,
        success=success,
        duration_ms=duration_ms,
        response_status=status_code,
    )

    # Record the delivery attempt
    if delivery_service and webhook_id:
        next_retry_at = _compute_next_retry_at(0) if not success else None
        try:
            await delivery_service.create(
                {
                    "webhook_id": webhook_id,
                    "endpoint_id": endpoint.id,
                    "event": event_type,
                    "endpoint_url": endpoint.url,
                    "payload": full_payload,
                    "status_code": status_code,
                    "response_time_ms": duration_ms,
                    "success": success,
                    "error": error_msg,
                    "retry_count": 0,
                    "max_retries": len(RETRY_BACKOFF_SECONDS),
                    "next_retry_at": next_retry_at,
                },
                auto_commit=True,
            )
        except Exception:  # noqa: BLE001
            await logger.aerror(
                "Failed to record webhook delivery",
                endpoint_id=str(endpoint.id),
                event_type=event_type,
            )


async def redeliver(
    delivery: m.WebhookDelivery,
    delivery_service: WebhookDeliveryService,
) -> bool:
    """Re-attempt delivery for a failed webhook delivery record.

    Sends the stored payload to the stored endpoint URL and updates
    the delivery record with the result.

    Args:
        delivery: The failed delivery record to retry.
        delivery_service: The service for updating the delivery record.

    Returns:
        True if the redelivery succeeded, False otherwise.
    """
    import msgspec

    if not delivery.payload or not delivery.endpoint_url:
        await logger.awarning(
            "Cannot redeliver — missing payload or endpoint URL",
            delivery_id=str(delivery.id),
        )
        # Mark as exhausted so we don't keep trying
        await delivery_service.update(
            {"next_retry_at": None},
            item_id=delivery.id,
            auto_commit=True,
        )
        return False

    payload_bytes = msgspec.json.encode(delivery.payload)

    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "User-Agent": "AdminPortal-Webhook/1.0",
        "X-Webhook-Event": delivery.event,
        "X-Webhook-Retry": str(delivery.retry_count + 1),
    }

    # If the endpoint still exists, use its secret for signing
    if delivery.endpoint:
        if delivery.endpoint.secret:
            headers["X-Webhook-Signature"] = _compute_signature(payload_bytes, delivery.endpoint.secret)
        if delivery.endpoint.headers:
            headers.update(delivery.endpoint.headers)

    start_time = time.monotonic()
    status_code: int | None = None
    success = False
    error_msg: str | None = None

    try:
        async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT_SECONDS) as client:
            response = await client.post(
                delivery.endpoint_url,
                content=payload_bytes,
                headers=headers,
            )
            status_code = response.status_code
            success = response.is_success

            if not success:
                error_msg = response.text[:WEBHOOK_MAX_RESPONSE_BODY_LENGTH] if response.text else None

    except httpx.TimeoutException:
        error_msg = "Request timed out"
    except httpx.RequestError as exc:
        error_msg = str(exc)
    except Exception as exc:  # noqa: BLE001
        error_msg = f"Unexpected error: {exc}"

    duration_ms = int((time.monotonic() - start_time) * 1000)
    new_retry_count = delivery.retry_count + 1
    next_retry_at = None if success else _compute_next_retry_at(new_retry_count)

    try:
        await delivery_service.update(
            {
                "status_code": status_code,
                "response_time_ms": duration_ms,
                "success": success,
                "error": error_msg,
                "retry_count": new_retry_count,
                "next_retry_at": next_retry_at,
            },
            item_id=delivery.id,
            auto_commit=True,
        )
    except Exception:  # noqa: BLE001
        await logger.aerror(
            "Failed to update webhook delivery record",
            delivery_id=str(delivery.id),
        )

    await logger.ainfo(
        "Webhook redelivery attempt",
        delivery_id=str(delivery.id),
        retry_count=new_retry_count,
        success=success,
        status_code=status_code,
        next_retry_at=str(next_retry_at) if next_retry_at else None,
    )

    return success
