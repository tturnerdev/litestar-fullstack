"""Attachment schemas."""

from datetime import datetime
from uuid import UUID

from app.lib.schema import CamelizedBaseStruct


class Attachment(CamelizedBaseStruct):
    """Metadata for an uploaded file."""

    id: UUID
    original_filename: str
    content_type: str
    size_bytes: int
    purpose: str
    uploaded_by_id: UUID | None
    team_id: UUID | None
    checksum_sha256: str | None
    created_at: datetime
    updated_at: datetime
    download_url: str | None = None
    """Relative URL to stream the file content (set by the controller)."""


class PresignRequest(CamelizedBaseStruct):
    """Request body for ``POST /api/uploads/presign``."""

    filename: str
    content_type: str = "application/octet-stream"
    purpose: str = "attachment"
    team_id: UUID | None = None


class PresignResponse(CamelizedBaseStruct):
    """Response body for ``POST /api/uploads/presign``."""

    upload_url: str
    """Presigned ``PUT`` URL — the client uploads the file directly here."""
    path: str
    """The object-storage path the client will pass to ``POST /api/uploads/complete``."""
    expires_in: int
    """Seconds until ``upload_url`` expires."""


class CompleteUploadRequest(CamelizedBaseStruct):
    """Request body for ``POST /api/uploads/complete``."""

    path: str
    original_filename: str
    content_type: str = "application/octet-stream"
    purpose: str = "attachment"
    team_id: UUID | None = None
