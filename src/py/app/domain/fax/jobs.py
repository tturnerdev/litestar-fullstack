"""Fax background jobs."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from app.domain.tasks.jobs import broadcast_entity_event, provide_task_context

if TYPE_CHECKING:
    from saq.types import Context

logger = structlog.get_logger()


async def fax_send_job(
    ctx: Context,
    *,
    task_id: str,
    fax_number_id: str,
    to_number: str,
    from_number: str,
    media_url: str | None = None,
) -> dict:
    """Send a fax via the configured fax provider.

    This is a placeholder that will be replaced with actual Telnyx API calls.
    The implementation should be provider-agnostic through a fax adapter interface.

    Args:
        ctx: SAQ job context.
        task_id: Background task ID for progress tracking.
        fax_number_id: The fax number record ID.
        to_number: Destination fax number.
        from_number: Originating fax number.
        media_url: URL of the document to fax.

    Returns:
        Dictionary with send result.
    """
    async with provide_task_context(ctx, task_id) as (task_service, task):
        await task_service.start_task(task.id)
        await logger.ainfo("Initiating fax send", to=to_number, from_number=from_number)

        # Phase 1: Validate and prepare
        await task_service.update_progress(task.id, 10)

        # Phase 2: Submit to fax provider
        # TODO: Call Telnyx API: POST https://api.telnyx.com/v2/faxes
        # Required: connection_id, to, from, media_url
        # Response includes fax ID for status tracking
        await task_service.update_progress(task.id, 30)

        # Phase 3: Monitor send status via webhook or polling
        # TODO: Telnyx sends webhook events: fax.queued -> fax.sending.started -> fax.delivered/fax.failed
        # For now, complete immediately as placeholder
        await task_service.update_progress(task.id, 100)

        task = await task_service.complete_task(task.id, result={
            "to_number": to_number,
            "from_number": from_number,
            "action": "fax.send",
            "provider": "telnyx",
        })
        await broadcast_entity_event(task)
    return {"status": "completed"}


async def fax_receive_process_job(ctx: Context, *, task_id: str, fax_message_id: str) -> dict:
    """Process a received fax -- convert format, deliver to email routes.

    Args:
        ctx: SAQ job context.
        task_id: Background task ID for progress tracking.
        fax_message_id: The fax message record ID to process.

    Returns:
        Dictionary with processing result.
    """
    async with provide_task_context(ctx, task_id) as (task_service, task):
        await task_service.start_task(task.id)
        await logger.ainfo("Processing received fax", fax_message_id=fax_message_id)

        # Phase 1: Retrieve fax document from provider
        await task_service.update_progress(task.id, 25)
        # TODO: Fetch fax document from Telnyx media URL

        # Phase 2: Look up email routes and deliver
        await task_service.update_progress(task.id, 50)
        # TODO: Query FaxEmailRoute for active routes, send emails with PDF attachment

        # Phase 3: Update fax message record
        await task_service.update_progress(task.id, 75)
        # TODO: Mark fax message as delivered, record which emails received it

        task = await task_service.complete_task(task.id, result={
            "fax_message_id": fax_message_id,
            "action": "fax.receive_process",
        })
        await broadcast_entity_event(task)
    return {"status": "completed"}
