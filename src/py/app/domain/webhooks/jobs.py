"""Webhook domain background jobs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from structlog import get_logger

from app.domain.webhooks import deps as webhook_deps
from app.lib.deps import provide_services

if TYPE_CHECKING:
    from saq.types import Context

__all__ = ("retry_failed_webhook_deliveries",)

logger = get_logger()


async def retry_failed_webhook_deliveries(_: Context) -> dict[str, int]:
    """SAQ cron job that retries failed webhook deliveries.

    Queries for deliveries where:
    - success is False
    - next_retry_at is not None and <= now
    - retry_count < max_retries

    For each eligible delivery, attempts redelivery using the dispatcher's
    redeliver function. Applies exponential backoff on continued failure.

    Returns:
        Dictionary with retry statistics.
    """
    from datetime import UTC, datetime

    from sqlalchemy import and_

    from app.db import models as m
    from app.domain.webhooks.services._webhook_dispatcher import redeliver

    retried = 0
    succeeded = 0
    failed = 0

    async with provide_services(webhook_deps.provide_webhook_delivery_service) as (delivery_service,):
        now = datetime.now(UTC)

        # Find deliveries eligible for retry, loading the endpoint relationship
        # so the redeliver function can access secret/headers if the endpoint
        # still exists.
        eligible_deliveries = await delivery_service.list(
            and_(
                m.WebhookDelivery.success.is_(False),
                m.WebhookDelivery.next_retry_at.isnot(None),
                m.WebhookDelivery.next_retry_at <= now,
                m.WebhookDelivery.retry_count < m.WebhookDelivery.max_retries,
            ),
            load=[m.WebhookDelivery.endpoint],
        )

        if not eligible_deliveries:
            await logger.adebug("No webhook deliveries eligible for retry")
            return {"retried": 0, "succeeded": 0, "failed": 0}

        await logger.ainfo(
            "Processing webhook delivery retries",
            eligible_count=len(eligible_deliveries),
        )

        for delivery in eligible_deliveries:
            retried += 1
            try:
                result = await redeliver(delivery, delivery_service)
                if result:
                    succeeded += 1
                else:
                    failed += 1
            except Exception:  # noqa: BLE001
                failed += 1
                await logger.aexception(
                    "Unexpected error during webhook redelivery",
                    delivery_id=str(delivery.id),
                )

    result_dict = {"retried": retried, "succeeded": succeeded, "failed": failed}
    await logger.ainfo("Webhook delivery retry complete", **result_dict)
    return result_dict
