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
