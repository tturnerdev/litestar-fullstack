"""Extension Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from litestar import Controller, get, patch
from litestar.params import Dependency, Parameter

from app.db import models as m
from app.domain.voice.guards import requires_extension_ownership
from app.domain.voice.schemas import Extension, ExtensionUpdate
from app.domain.voice.services import ExtensionService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination


class ExtensionController(Controller):
    """Extensions."""

    tags = ["Voice - Extensions"]
    path = "/api/voice/extensions"
    dependencies = create_service_dependencies(
        ExtensionService,
        key="extensions_service",
        filters={
            "id_filter": UUID,
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    )

    @get(operation_id="ListExtensions")
    async def list_extensions(
        self,
        extensions_service: ExtensionService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[Extension]:
        """List user's extensions."""
        results, total = await extensions_service.list_and_count(
            *filters,
            m.Extension.user_id == current_user.id,
        )
        return extensions_service.to_schema(results, total, filters, schema_type=Extension)

    @get(operation_id="GetExtension", path="/{ext_id:uuid}", guards=[requires_extension_ownership])
    async def get_extension(
        self,
        extensions_service: ExtensionService,
        current_user: m.User,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension to retrieve.")],
    ) -> Extension:
        """Get extension details."""
        db_obj = await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        return extensions_service.to_schema(db_obj, schema_type=Extension)

    @patch(operation_id="UpdateExtension", path="/{ext_id:uuid}", guards=[requires_extension_ownership])
    async def update_extension(
        self,
        extensions_service: ExtensionService,
        current_user: m.User,
        data: ExtensionUpdate,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension to update.")],
    ) -> Extension:
        """Update display name, settings."""
        db_obj = await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        db_obj = await extensions_service.update(item_id=db_obj.id, data=data.to_dict())
        return extensions_service.to_schema(db_obj, schema_type=Extension)
