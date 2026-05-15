"""Voicemail Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

import msgspec
from litestar import Controller, delete, get, patch
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from litestar.status_codes import HTTP_204_NO_CONTENT
from sqlalchemy.orm import selectinload
from structlog import get_logger

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.gateway.deps import provide_gateway_connections
from app.domain.gateway.providers import FreePBXProvider
from app.domain.teams.guards import requires_feature_permission
from app.domain.voice.deps import provide_extensions_service
from app.domain.voice.guards import requires_extension_ownership
from app.domain.voice.schemas import (
    VoicemailMessage,
    VoicemailMessageUpdate,
    VoicemailSettings,
    VoicemailSettingsUpdate,
)
from app.domain.voice.services import ExtensionService, VoicemailBoxService, VoicemailMessageService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

logger = get_logger()

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class VoicemailController(Controller):
    """Voicemail settings and messages."""

    tags = ["Voice Voicemail"]
    signature_types = [
        ExtensionService,
        VoicemailBoxService,
        VoicemailMessageService,
        VoicemailMessage,
        VoicemailMessageUpdate,
        VoicemailSettings,
        VoicemailSettingsUpdate,
    ]
    dependencies = (
        create_service_dependencies(
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
                "search": "caller_number,caller_name,transcription",
            },
        )
        | create_service_dependencies(
            VoicemailBoxService,
            key="voicemail_boxes_service",
            load=[selectinload(m.VoicemailBox.extension)],
        )
        | {
            "extensions_service": Provide(provide_extensions_service),
            "audit_service": Provide(provide_audit_log_service),
            "gateway_connections": Provide(provide_gateway_connections),
        }
    )

    @get(
        operation_id="GetVoicemailSettings",
        summary="Get voicemail settings",
        description="Retrieve the voicemail box configuration for an extension, creating a default box if one does not exist. The caller must own the extension.",
        path="/api/voice/extensions/{ext_id:uuid}/voicemail",
        guards=[requires_feature_permission("voice_voicemail", "view"), requires_extension_ownership],
    )
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
        result = voicemail_boxes_service.to_schema(db_obj, schema_type=VoicemailSettings)
        result.pin_set = db_obj.pin is not None
        return result

    @patch(
        operation_id="UpdateVoicemailSettings",
        summary="Update voicemail settings",
        description="Update voicemail box settings such as PIN, email address, or attachment preferences. If PBX-related fields change and a FreePBX connection exists, the voicemail configuration is synced to the PBX. Logs an audit entry.",
        path="/api/voice/extensions/{ext_id:uuid}/voicemail",
        guards=[requires_feature_permission("voice_voicemail", "edit"), requires_extension_ownership],
    )
    async def update_voicemail_settings(
        self,
        request: Request[m.User, Token, Any],
        extensions_service: ExtensionService,
        voicemail_boxes_service: VoicemailBoxService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: VoicemailSettingsUpdate,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
        gateway_connections: list[m.Connection],
    ) -> VoicemailSettings:
        """Update voicemail settings."""
        extension = await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        db_obj = await voicemail_boxes_service.get_or_create_for_extension(ext_id)
        before = capture_snapshot(db_obj)
        db_obj = await voicemail_boxes_service.update(item_id=db_obj.id, data=data.to_dict())
        after = capture_snapshot(db_obj)
        result = voicemail_boxes_service.to_schema(db_obj, schema_type=VoicemailSettings)
        result.pin_set = db_obj.pin is not None
        await log_audit(
            audit_service,
            action="voice.voicemail.updated",
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
        request.app.emit(event_id="voicemail_box_updated", voicemail_box_id=db_obj.id)

        pbx_fields = ("is_enabled", "pin", "email_address", "email_attach_audio")
        has_pbx_change = any(not isinstance(getattr(data, f), type(msgspec.UNSET)) for f in pbx_fields)
        pbx_connections = [c for c in gateway_connections if c.provider == "freepbx" and c.is_enabled]
        await logger.ainfo(
            "voicemail_pbx_check",
            ext=extension.extension_number,
            has_pbx_change=has_pbx_change,
            total_connections=len(gateway_connections),
            pbx_connections=len(pbx_connections),
            data_fields={f: repr(getattr(data, f)) for f in pbx_fields},
        )
        if has_pbx_change and pbx_connections:
            conn = pbx_connections[0]
            provider = FreePBXProvider()
            ext_num = extension.extension_number
            try:
                if db_obj.is_enabled:
                    await provider.enable_voicemail_on_pbx(
                        ext_num,
                        conn,
                        password=db_obj.pin or ext_num,
                        name=extension.display_name,
                        email=db_obj.email_address or current_user.email or "",
                        attach=db_obj.email_attach_audio,
                    )
                else:
                    await provider.disable_voicemail_on_pbx(ext_num, conn)
            except Exception as exc:
                await logger.awarning("pbx_voicemail_update_failed", ext=ext_num, error=str(exc))

        return result

    @get(
        operation_id="ListVoicemailMessages",
        summary="List voicemail messages",
        description="Retrieve a paginated list of voicemail messages for an extension's mailbox. Supports search by caller number, caller name, or transcription text. The caller must own the extension.",
        path="/api/voice/extensions/{ext_id:uuid}/voicemail/messages",
        guards=[requires_feature_permission("voice_voicemail", "view"), requires_extension_ownership],
    )
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
        summary="Get a voicemail message",
        description="Retrieve a single voicemail message by ID. Verifies the message belongs to the extension's voicemail box. The caller must own the extension.",
        path="/api/voice/extensions/{ext_id:uuid}/voicemail/messages/{msg_id:uuid}",
        guards=[requires_feature_permission("voice_voicemail", "view"), requires_extension_ownership],
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
        summary="Update a voicemail message",
        description="Update a voicemail message's metadata such as read/unread status. Logs an audit entry and emits an update event. The caller must own the extension.",
        path="/api/voice/extensions/{ext_id:uuid}/voicemail/messages/{msg_id:uuid}",
        guards=[requires_feature_permission("voice_voicemail", "edit"), requires_extension_ownership],
    )
    async def update_voicemail_message(
        self,
        request: Request[m.User, Token, Any],
        extensions_service: ExtensionService,
        voicemail_boxes_service: VoicemailBoxService,
        voicemail_messages_service: VoicemailMessageService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: VoicemailMessageUpdate,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
        msg_id: Annotated[UUID, Parameter(title="Message ID", description="The voicemail message.")],
    ) -> VoicemailMessage:
        """Mark read/unread."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        voicemail_box = await voicemail_boxes_service.get_one(extension_id=ext_id)
        db_obj = await voicemail_messages_service.get_one(id=msg_id, voicemail_box_id=voicemail_box.id)
        before = capture_snapshot(db_obj)
        db_obj = await voicemail_messages_service.update(item_id=db_obj.id, data=data.to_dict())
        after = capture_snapshot(db_obj)
        result = voicemail_messages_service.to_schema(db_obj, schema_type=VoicemailMessage)
        await log_audit(
            audit_service,
            action="voice.voicemail_message.updated",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="voicemail_message",
            target_id=msg_id,
            target_label=db_obj.caller_number,
            before=before,
            after=after,
            request=request,
        )
        request.app.emit(event_id="voicemail_message_updated", message_id=msg_id)
        return result

    @delete(
        operation_id="DeleteVoicemailMessage",
        summary="Delete a voicemail message",
        description="Permanently delete a voicemail message from the extension's mailbox. Logs an audit entry and emits a deletion event. The caller must own the extension.",
        path="/api/voice/extensions/{ext_id:uuid}/voicemail/messages/{msg_id:uuid}",
        return_dto=None,
        guards=[requires_feature_permission("voice_voicemail", "edit"), requires_extension_ownership],
        status_code=HTTP_204_NO_CONTENT,
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
        request.app.emit(event_id="voicemail_message_deleted", message_id=msg_id)
        await voicemail_messages_service.delete(msg_id)
        await log_audit(
            audit_service,
            action="voice.voicemail.deleted",
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
