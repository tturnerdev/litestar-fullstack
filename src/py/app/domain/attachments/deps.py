"""Attachments domain dependencies."""

from __future__ import annotations

from app.domain.attachments.services import AttachmentService
from app.lib.deps import create_service_provider

provide_attachments_service = create_service_provider(
    AttachmentService,
    error_messages={"integrity": "Attachment operation failed."},
)

__all__ = ("provide_attachments_service",)
