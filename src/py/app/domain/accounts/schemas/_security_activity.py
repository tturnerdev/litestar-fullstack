"""Security activity schemas for user profile."""

from datetime import datetime
from uuid import UUID

from app.lib.schema import CamelizedBaseStruct


class SecurityActivityEntry(CamelizedBaseStruct, kw_only=True):
    """A single security-relevant audit event for the current user."""

    id: UUID
    action: str
    description: str
    created_at: datetime
    ip_address: str | None = None
