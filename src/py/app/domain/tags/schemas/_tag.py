"""Tag schemas."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.lib.schema import CamelizedBaseStruct


class Tag(CamelizedBaseStruct):
    """Tag Information."""

    id: UUID
    slug: str
    name: str
    created_at: datetime
    updated_at: datetime
    description: str | None = None


class TagCreate(CamelizedBaseStruct):
    """Tag Create Properties."""

    name: Annotated[str, Meta(min_length=1, max_length=100)]
    description: Annotated[str, Meta(min_length=1, max_length=255)] | None = None


class TagUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Tag Update Properties."""

    name: Annotated[str, Meta(min_length=1, max_length=100)] | msgspec.UnsetType = msgspec.UNSET
    description: Annotated[str, Meta(min_length=1, max_length=255)] | None | msgspec.UnsetType = msgspec.UNSET
