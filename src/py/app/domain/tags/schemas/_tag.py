"""Tag schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct


class Tag(CamelizedBaseStruct):
    """Tag Information."""

    id: UUID
    slug: str
    name: str
    created_at: datetime
    updated_at: datetime


class TagCreate(CamelizedBaseStruct):
    """Tag Create Properties."""

    name: Annotated[str, Meta(min_length=1, max_length=100)]


class TagUpdate(CamelizedBaseStruct):
    """Tag Update Properties."""

    name: Annotated[str, Meta(min_length=1, max_length=100)] | None = None
