"""Voicemail Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch
from litestar.di import Provide
from litestar.params import Dependency, Parameter

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.voice.deps import (
    provide_extensions_service,
    provide_voicemail_boxes_service,
)
from app.domain.voice.guards import requires_extension_ownership
from app.domain.voice.schemas import (
    VoicemailMessage,
    VoicemailMessageUpdate,
    VoicemailSettings,
    VoicemailSettingsUpdate,
)
from app.domain.voice.services import VoicemailMessageService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService
    from app.domain.voice.services import ExtensionService, VoicemailBoxService


class VoicemailController(Controller):
    """Voicemail settings and messages."""

    tags = ["Voice - Voicemail"]
    guards = [requires_extension_ownership]
    dependencies = {
        "extensions_service": Provide(provide_extensions_service),
        "voicemail_boxes_service": Provide(provide_voicemail_boxes_service),
        "audit_service": Provide(provide_audit_log_service),
        **create_service_dependencies(
            VoicemailMessageService,
            key="voicemail_messages_service",
            filters={
                "id_filter": UUID,
                "pagination_type": "limit_offset",
                "pagination_size": 20,
                "created_at": True,
                "updated_at": True,
                "sort_field": "created_at",
                "sort_order": "desc",
            },
        ),
    }

    @get(operation_id="GetVoicemailSettings", path="/api/voice/extensions/{ext_id:uuid}/voicemail")
    async def get_voicemail_settings(
        self,
        extensions_service: ExtensionService,
        voicemail_boxes_service: VoicemailBoxService,
        current_user: m.User,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
    ) -> VoicemailSettings:
        """Get voicemail box config."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        db_obj = await voicemail_boxes_service.get_or_create_for_extension(ext_id)
        return voicemail_boxes_service.to_schema(db_obj, schema_type=VoicemailSettings)

    @patch(operation_id="UpdateVoicemailSettings", path="/api/voice/extensions/{ext_id:uuid}/voicemail")
    async def update_voicemail_settings(
        self,
        request: Request[m.User, Token, Any],
        extensions_service: ExtensionService,
        voicemail_boxes_service: VoicemailBoxService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: VoicemailSettingsUpdate,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
    ) -> VoicemailSettings:
        """Update voicemail settings."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        db_obj = await voicemail_boxes_service.get_or_create_for_extension(ext_id)
        before = capture_snapshot(db_obj)
        db_obj = await voicemail_boxes_service.update(item_id=db_obj.id, data=data.to_dict())
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="voice.voicemail_update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="voicemail_box",
            target_id=db_obj.id,
            target_label=f"extension:{ext_id}",
            before=before,
            after=after,
            request=request,
        )
        return voicemail_boxes_service.to_schema(db_obj, schema_type=VoicemailSettings)

    @get(operation_id="ListVoicemailMessages", path="/api/voice/extensions/{ext_id:uuid}/voicemail/messages")
    async def list_voicemail_messages(
        self,
        extensions_service: ExtensionService,
        voicemail_boxes_service: VoicemailBoxService,
        voicemail_messages_service: VoicemailMessageService,
        current_user: m.User,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[VoicemailMessage]:
        """List messages (paginated)."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        voicemail_box = await voicemail_boxes_service.get_or_create_for_extension(ext_id)
        results, total = await voicemail_messages_service.list_and_count(
            *filters,
            m.VoicemailMessage.voicemail_box_id == voicemail_box.id,
        )
        return voicemail_messages_service.to_schema(results, total, filters, schema_type=VoicemailMessage)

    @get(
        operation_id="GetVoicemailMessage",
        path="/api/voice/extensions/{ext_id:uuid}/voicemail/messages/{msg_id:uuid}",
    )
    async def get_voicemail_message(
        self,
        extensions_service: ExtensionService,
        voicemail_boxes_service: VoicemailBoxService,
        voicemail_messages_service: VoicemailMessageService,
        current_user: m.User,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
        msg_id: Annotated[UUID, Parameter(title="Message ID", description="The voicemail message.")],
    ) -> VoicemailMessage:
        """Get message details."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        voicemail_box = await voicemail_boxes_service.get_one(extension_id=ext_id)
        db_obj = await voicemail_messages_service.get_one(id=msg_id, voicemail_box_id=voicemail_box.id)
        return voicemail_messages_service.to_schema(db_obj, schema_type=VoicemailMessage)

    @patch(
        operation_id="UpdateVoicemailMessage",
        path="/api/voice/extensions/{ext_id:uuid}/voicemail/messages/{msg_id:uuid}",
    )
    async def update_voicemail_message(
        self,
        extensions_service: ExtensionService,
        voicemail_boxes_service: VoicemailBoxService,
        voicemail_messages_service: VoicemailMessageService,
        current_user: m.User,
        data: VoicemailMessageUpdate,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
        msg_id: Annotated[UUID, Parameter(title="Message ID", description="The voicemail message.")],
    ) -> VoicemailMessage:
        """Mark read/unread."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        voicemail_box = await voicemail_boxes_service.get_one(extension_id=ext_id)
        db_obj = await voicemail_messages_service.get_one(id=msg_id, voicemail_box_id=voicemail_box.id)
        db_obj = await voicemail_messages_service.update(item_id=db_obj.id, data=data.to_dict())
        return voicemail_messages_service.to_schema(db_obj, schema_type=VoicemailMessage)

    @delete(
        operation_id="DeleteVoicemailMessage",
        path="/api/voice/extensions/{ext_id:uuid}/voicemail/messages/{msg_id:uuid}",
        return_dto=None,
    )
    async def delete_voicemail_message(
        self,
        request: Request[m.User, Token, Any],
        extensions_service: ExtensionService,
        voicemail_boxes_service: VoicemailBoxService,
        voicemail_messages_service: VoicemailMessageService,
        audit_service: AuditLogService,
        current_user: m.User,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
        msg_id: Annotated[UUID, Parameter(title="Message ID", description="The voicemail message.")],
    ) -> None:
        """Delete a message."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        voicemail_box = await voicemail_boxes_service.get_one(extension_id=ext_id)
        db_obj = await voicemail_messages_service.get_one(id=msg_id, voicemail_box_id=voicemail_box.id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.caller_number
        await voicemail_messages_service.delete(msg_id)
        await log_audit(
            audit_service,
            action="voice.voicemail_delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="voicemail_message",
            target_id=msg_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )
