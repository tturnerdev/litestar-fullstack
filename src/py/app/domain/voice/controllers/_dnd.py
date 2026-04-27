"""Do Not Disturb Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from litestar import Controller, get, patch, post
from litestar.di import Provide
from litestar.params import Parameter

from app.domain.voice.deps import provide_dnd_service, provide_extensions_service
from app.domain.voice.guards import requires_extension_ownership
from app.domain.voice.schemas import DndSettings, DndSettingsUpdate, DndToggleResponse

if TYPE_CHECKING:
    from uuid import UUID

    from app.db import models as m
    from app.domain.voice.services import DoNotDisturbService, ExtensionService


class DndController(Controller):
    """Do Not Disturb."""

    tags = ["Voice - DND"]
    guards = [requires_extension_ownership]
    dependencies = {
        "extensions_service": Provide(provide_extensions_service),
        "dnd_service": Provide(provide_dnd_service),
    }

    @get(operation_id="GetDndSettings", path="/api/voice/extensions/{ext_id:uuid}/dnd")
    async def get_dnd_settings(
        self,
        extensions_service: ExtensionService,
        dnd_service: DoNotDisturbService,
        current_user: m.User,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
    ) -> DndSettings:
        """Get DND configuration."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        db_obj = await dnd_service.get_one(extension_id=ext_id)
        return dnd_service.to_schema(db_obj, schema_type=DndSettings)

    @patch(operation_id="UpdateDndSettings", path="/api/voice/extensions/{ext_id:uuid}/dnd")
    async def update_dnd_settings(
        self,
        extensions_service: ExtensionService,
        dnd_service: DoNotDisturbService,
        current_user: m.User,
        data: DndSettingsUpdate,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
    ) -> DndSettings:
        """Update DND settings."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        db_obj = await dnd_service.get_one(extension_id=ext_id)
        db_obj = await dnd_service.update(item_id=db_obj.id, data=data.to_dict())
        return dnd_service.to_schema(db_obj, schema_type=DndSettings)

    @post(operation_id="ToggleDnd", path="/api/voice/extensions/{ext_id:uuid}/dnd/toggle")
    async def toggle_dnd(
        self,
        extensions_service: ExtensionService,
        dnd_service: DoNotDisturbService,
        current_user: m.User,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
    ) -> DndToggleResponse:
        """Quick toggle DND on/off."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        db_obj = await dnd_service.get_one(extension_id=ext_id)
        db_obj = await dnd_service.update(item_id=db_obj.id, data={"is_enabled": not db_obj.is_enabled})
        return dnd_service.to_schema(db_obj, schema_type=DndToggleResponse)
