"""Voicemail Message Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, put
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.voicemail.guards import requires_voicemail_message_access
from app.domain.voicemail.schemas import VoicemailMessage, VoicemailReadToggle
from app.domain.voicemail.services import VoicemailBoxService, VoicemailMessageService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class VoicemailMessageController(Controller):
    """Voicemail Messages."""

    tags = ["Voicemail"]
    dependencies = create_service_dependencies(
        VoicemailMessageService,
        key="voicemail_messages_service",
        load=[selectinload(m.VoicemailMessage.voicemail_box)],
        filters={
            "id_filter": UUID,
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "received_at",
            "sort_order": "desc",
        },
    ) | create_service_dependencies(
        VoicemailBoxService,
        key="voicemail_boxes_service",
        load=[selectinload(m.VoicemailBox.extension)],
    ) | {
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(operation_id="ListAllVoicemailMessages", path="/api/voicemail/messages")
    async def list_voicemail_messages(
        self,
        voicemail_messages_service: VoicemailMessageService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
        is_read: bool | None = None,
        is_urgent: bool | None = None,
    ) -> OffsetPagination[VoicemailMessage]:
        """List all voicemail messages (admin-wide).

        Superusers see all messages. Regular users see only messages
        for their extensions' voicemail boxes.

        Args:
            voicemail_messages_service: Voicemail Message Service
            current_user: Current User
            filters: Filters
            is_read: Optional filter by read status
            is_urgent: Optional filter by urgency

        Returns:
            OffsetPagination[VoicemailMessage]
        """
        extra_filters = []
        if is_read is not None:
            extra_filters.append(m.VoicemailMessage.is_read == is_read)
        if is_urgent is not None:
            extra_filters.append(m.VoicemailMessage.is_urgent == is_urgent)

        if current_user.is_superuser:
            results, total = await voicemail_messages_service.list_and_count(
                *filters, *extra_filters
            )
        else:
            user_box_ids = (
                select(m.VoicemailBox.id)
                .join(m.Extension, m.VoicemailBox.extension_id == m.Extension.id)
                .where(m.Extension.user_id == current_user.id)
                .scalar_subquery()
            )
            results, total = await voicemail_messages_service.list_and_count(
                *filters,
                *extra_filters,
                m.VoicemailMessage.voicemail_box_id.in_(user_box_ids),
            )
        return voicemail_messages_service.to_schema(results, total, filters, schema_type=VoicemailMessage)

    @get(
        operation_id="ListVoicemailBoxMessages",
        path="/api/voicemail/boxes/{box_id:uuid}/messages",
        guards=[requires_voicemail_message_access],
    )
    async def list_box_messages(
        self,
        voicemail_messages_service: VoicemailMessageService,
        voicemail_boxes_service: VoicemailBoxService,
        box_id: Annotated[UUID, Parameter(title="Box ID", description="The voicemail box.")],
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
        is_read: bool | None = None,
        is_urgent: bool | None = None,
    ) -> OffsetPagination[VoicemailMessage]:
        """List messages for a specific voicemail box.

        Args:
            voicemail_messages_service: Voicemail Message Service
            voicemail_boxes_service: Voicemail Box Service
            box_id: Voicemail Box ID
            filters: Filters
            is_read: Optional filter by read status
            is_urgent: Optional filter by urgency

        Returns:
            OffsetPagination[VoicemailMessage]
        """
        await voicemail_boxes_service.get(box_id)
        extra_filters = [m.VoicemailMessage.voicemail_box_id == box_id]
        if is_read is not None:
            extra_filters.append(m.VoicemailMessage.is_read == is_read)
        if is_urgent is not None:
            extra_filters.append(m.VoicemailMessage.is_urgent == is_urgent)

        results, total = await voicemail_messages_service.list_and_count(
            *filters, *extra_filters
        )
        return voicemail_messages_service.to_schema(results, total, filters, schema_type=VoicemailMessage)

    @get(
        operation_id="GetVoicemailMessageById",
        path="/api/voicemail/messages/{message_id:uuid}",
        guards=[requires_voicemail_message_access],
    )
    async def get_voicemail_message(
        self,
        voicemail_messages_service: VoicemailMessageService,
        message_id: Annotated[UUID, Parameter(title="Message ID", description="The voicemail message to retrieve.")],
    ) -> VoicemailMessage:
        """Get details about a voicemail message.

        Args:
            voicemail_messages_service: Voicemail Message Service
            message_id: Message ID

        Returns:
            VoicemailMessage
        """
        db_obj = await voicemail_messages_service.get(message_id)
        return voicemail_messages_service.to_schema(db_obj, schema_type=VoicemailMessage)

    @put(
        operation_id="ToggleVoicemailMessageRead",
        path="/api/voicemail/messages/{message_id:uuid}/read",
        guards=[requires_voicemail_message_access],
    )
    async def toggle_read_status(
        self,
        voicemail_messages_service: VoicemailMessageService,
        message_id: Annotated[UUID, Parameter(title="Message ID", description="The voicemail message.")],
        data: VoicemailReadToggle,
    ) -> VoicemailMessage:
        """Toggle the read status of a voicemail message.

        Args:
            voicemail_messages_service: Voicemail Message Service
            message_id: Message ID
            data: Read toggle payload

        Returns:
            VoicemailMessage
        """
        if data.is_read:
            db_obj = await voicemail_messages_service.mark_read(message_id)
        else:
            db_obj = await voicemail_messages_service.mark_unread(message_id)
        return voicemail_messages_service.to_schema(db_obj, schema_type=VoicemailMessage)

    @delete(
        operation_id="DeleteVoicemailMessageById",
        path="/api/voicemail/messages/{message_id:uuid}",
        guards=[requires_voicemail_message_access],
    )
    async def delete_voicemail_message(
        self,
        request: Request[m.User, Token, Any],
        voicemail_messages_service: VoicemailMessageService,
        audit_service: AuditLogService,
        current_user: m.User,
        message_id: Annotated[UUID, Parameter(title="Message ID", description="The voicemail message to delete.")],
    ) -> None:
        """Delete a voicemail message.

        Args:
            request: The current request
            voicemail_messages_service: Voicemail Message Service
            audit_service: Audit Log Service
            current_user: Current User
            message_id: Message ID
        """
        db_obj = await voicemail_messages_service.get(message_id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.caller_number
        await voicemail_messages_service.delete(message_id)
        await log_audit(
            audit_service,
            action="voicemail.message.deleted",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="voicemail_message",
            target_id=message_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )
