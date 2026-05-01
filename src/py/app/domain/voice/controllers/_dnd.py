"""Do Not Disturb Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any

from litestar import Controller, get, patch, post
from litestar.di import Provide
from litestar.params import Parameter

from app.domain.admin.deps import provide_audit_log_service
from app.domain.teams.guards import requires_feature_permission
from app.domain.voice.deps import provide_dnd_service, provide_extensions_service
from app.domain.voice.guards import requires_extension_ownership
from app.domain.voice.schemas import DndSettings, DndSettingsUpdate, DndToggleResponse
from app.lib.audit import capture_snapshot, log_audit

if TYPE_CHECKING:
    from uuid import UUID

    from litestar import Request
    from litestar.security.jwt import Token

    from app.db import models as m
    from app.domain.admin.services import AuditLogService
    from app.domain.voice.services import DoNotDisturbService, ExtensionService


class DndController(Controller):
    """Do Not Disturb."""

    tags = ["Voice - DND"]
    dependencies = {
        "extensions_service": Provide(provide_extensions_service),
        "dnd_service": Provide(provide_dnd_service),
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(
        operation_id="GetDndSettings",
        path="/api/voice/extensions/{ext_id:uuid}/dnd",
        guards=[requires_feature_permission("voice", "view"), requires_extension_ownership],
    )
    async def get_dnd_settings(
        self,
        extensions_service: ExtensionService,
        dnd_service: DoNotDisturbService,
        current_user: m.User,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
    ) -> DndSettings:
        """Get DND configuration."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        db_obj = await dnd_service.get_or_create_for_extension(ext_id)
        return dnd_service.to_schema(db_obj, schema_type=DndSettings)

    @patch(
        operation_id="UpdateDndSettings",
        path="/api/voice/extensions/{ext_id:uuid}/dnd",
        guards=[requires_feature_permission("voice", "edit"), requires_extension_ownership],
    )
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
        db_obj = await dnd_service.get_or_create_for_extension(ext_id)
        db_obj = await dnd_service.update(item_id=db_obj.id, data=data.to_dict())
        return dnd_service.to_schema(db_obj, schema_type=DndSettings)

    @post(
        operation_id="ToggleDnd",
        path="/api/voice/extensions/{ext_id:uuid}/dnd/toggle",
        guards=[requires_feature_permission("voice", "edit"), requires_extension_ownership],
    )
    async def toggle_dnd(
        self,
        request: Request[m.User, Token, Any],
        extensions_service: ExtensionService,
        dnd_service: DoNotDisturbService,
        audit_service: AuditLogService,
        current_user: m.User,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
    ) -> DndToggleResponse:
        """Quick toggle DND on/off."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        db_obj = await dnd_service.get_or_create_for_extension(ext_id)
        before = capture_snapshot(db_obj)
        db_obj = await dnd_service.update(item_id=db_obj.id, data={"is_enabled": not db_obj.is_enabled})
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="voice.dnd.toggled",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="dnd",
            target_id=db_obj.id,
            target_label=f"extension:{ext_id}",
            before=before,
            after=after,
            request=request,
        )
        return dnd_service.to_schema(db_obj, schema_type=DndToggleResponse)
