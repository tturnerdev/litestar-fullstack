"""Attachments domain background jobs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from structlog import get_logger

from app.domain.attachments.deps import provide_attachments_service
from app.lib.deps import provide_services

if TYPE_CHECKING:
    from saq.types import Context

__all__ = ("cleanup_orphan_attachments",)

logger = get_logger()


async def cleanup_orphan_attachments(_: Context) -> dict[str, int]:
    """Delete objects in the storage bucket that no attachment row references.

    Returns:
        Counts of objects scanned, kept, and deleted.
    """
    async with provide_services(provide_attachments_service) as (attachments_service,):
        result = await attachments_service.cleanup_orphan_objects()
    await logger.ainfo("Orphan attachment cleanup complete", **result)
    return result
