"""Voicemail Box Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.notifications.deps import provide_notifications_service
from app.domain.voicemail.guards import requires_voicemail_access
from app.domain.voicemail.schemas import VoicemailBox, VoicemailBoxCreate, VoicemailBoxUpdate, VoicemailUnreadCount
from app.domain.voicemail.services import VoicemailBoxService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService
    from app.domain.notifications.services import NotificationService


class VoicemailBoxController(Controller):
    """Voicemail Boxes."""

    tags = ["Voicemail"]
    dependencies = create_service_dependencies(
        VoicemailBoxService,
        key="voicemail_boxes_service",
        load=[selectinload(m.VoicemailBox.extension)],
        filters={
            "id_filter": UUID,
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    ) | {
        "audit_service": Provide(provide_audit_log_service),
        "notifications_service": Provide(provide_notifications_service),
    }

    @get(operation_id="ListVoicemailBoxes", path="/api/voicemail/boxes")
    async def list_voicemail_boxes(
        self,
        voicemail_boxes_service: VoicemailBoxService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[VoicemailBox]:
        """List voicemail boxes the current user can access.

        Superusers see all boxes. Regular users see only boxes for their extensions.

        Args:
            voicemail_boxes_service: Voicemail Box Service
            current_user: Current User
            filters: Filters

        Returns:
            OffsetPagination[VoicemailBox]
        """
        if current_user.is_superuser:
            results, total = await voicemail_boxes_service.list_and_count(*filters)
        else:
            user_extension_ids = (
                select(m.Extension.id)
                .where(m.Extension.user_id == current_user.id)
                .scalar_subquery()
            )
            results, total = await voicemail_boxes_service.list_and_count(
                *filters,
                m.VoicemailBox.extension_id.in_(user_extension_ids),
            )
        return voicemail_boxes_service.to_schema(results, total, filters, schema_type=VoicemailBox)

    @post(operation_id="CreateVoicemailBox", path="/api/voicemail/boxes")
    async def create_voicemail_box(
        self,
        request: Request[m.User, Token, Any],
        voicemail_boxes_service: VoicemailBoxService,
        audit_service: AuditLogService,
        notifications_service: NotificationService,
        current_user: m.User,
        data: VoicemailBoxCreate,
    ) -> VoicemailBox:
        """Create a new voicemail box.

        Args:
            request: The current request
            voicemail_boxes_service: Voicemail Box Service
            audit_service: Audit Log Service
            notifications_service: Notification Service
            current_user: Current User
            data: Voicemail Box Create

        Returns:
            VoicemailBox
        """
        obj = data.to_dict()
        db_obj = await voicemail_boxes_service.create(obj)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="voicemail.box_create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="voicemail_box",
            target_id=db_obj.id,
            target_label=f"extension:{db_obj.extension_id}",
            before=None,
            after=after,
            request=request,
        )
        try:
            await notifications_service.notify(
                user_id=current_user.id,
                title="Voicemail Box Created",
                message="A new voicemail box has been configured.",
                category="voicemail",
                action_url=f"/voicemail/boxes/{db_obj.id}",
            )
        except Exception:
            pass
        return voicemail_boxes_service.to_schema(db_obj, schema_type=VoicemailBox)

    @get(
        operation_id="GetVoicemailBox",
        path="/api/voicemail/boxes/{box_id:uuid}",
        guards=[requires_voicemail_access],
    )
    async def get_voicemail_box(
        self,
        voicemail_boxes_service: VoicemailBoxService,
        box_id: Annotated[UUID, Parameter(title="Box ID", description="The voicemail box to retrieve.")],
    ) -> VoicemailBox:
        """Get details about a voicemail box.

        Args:
            voicemail_boxes_service: Voicemail Box Service
            box_id: Voicemail Box ID

        Returns:
            VoicemailBox
        """
        db_obj = await voicemail_boxes_service.get(box_id)
        return voicemail_boxes_service.to_schema(db_obj, schema_type=VoicemailBox)

    @patch(
        operation_id="UpdateVoicemailBox",
        path="/api/voicemail/boxes/{box_id:uuid}",
        guards=[requires_voicemail_access],
    )
    async def update_voicemail_box(
        self,
        request: Request[m.User, Token, Any],
        data: VoicemailBoxUpdate,
        voicemail_boxes_service: VoicemailBoxService,
        audit_service: AuditLogService,
        current_user: m.User,
        box_id: Annotated[UUID, Parameter(title="Box ID", description="The voicemail box to update.")],
    ) -> VoicemailBox:
        """Update a voicemail box.

        Args:
            request: The current request
            data: Voicemail Box Update
            voicemail_boxes_service: Voicemail Box Service
            audit_service: Audit Log Service
            current_user: Current User
            box_id: Voicemail Box ID

        Returns:
            VoicemailBox
        """
        before = capture_snapshot(await voicemail_boxes_service.get(box_id))
        db_obj = await voicemail_boxes_service.update(item_id=box_id, data=data.to_dict())
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="voicemail.box_update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="voicemail_box",
            target_id=box_id,
            target_label=f"extension:{db_obj.extension_id}",
            before=before,
            after=after,
            request=request,
        )
        return voicemail_boxes_service.to_schema(db_obj, schema_type=VoicemailBox)

    @delete(
        operation_id="DeleteVoicemailBox",
        path="/api/voicemail/boxes/{box_id:uuid}",
        guards=[requires_voicemail_access],
    )
    async def delete_voicemail_box(
        self,
        request: Request[m.User, Token, Any],
        voicemail_boxes_service: VoicemailBoxService,
        audit_service: AuditLogService,
        notifications_service: NotificationService,
        current_user: m.User,
        box_id: Annotated[UUID, Parameter(title="Box ID", description="The voicemail box to delete.")],
    ) -> None:
        """Delete a voicemail box and all its messages.

        Args:
            request: The current request
            voicemail_boxes_service: Voicemail Box Service
            audit_service: Audit Log Service
            notifications_service: Notification Service
            current_user: Current User
            box_id: Voicemail Box ID
        """
        db_obj = await voicemail_boxes_service.get(box_id)
        before = capture_snapshot(db_obj)
        target_label = f"extension:{db_obj.extension_id}"
        await voicemail_boxes_service.delete(box_id)
        await log_audit(
            audit_service,
            action="voicemail.box_delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="voicemail_box",
            target_id=box_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )
        try:
            await notifications_service.notify(
                user_id=current_user.id,
                title="Voicemail Box Removed",
                message="A voicemail box has been removed.",
                category="voicemail",
                action_url="/voicemail/boxes",
            )
        except Exception:
            pass

    @get(
        operation_id="GetVoicemailBoxUnreadCount",
        path="/api/voicemail/boxes/{box_id:uuid}/unread",
        guards=[requires_voicemail_access],
    )
    async def get_unread_count(
        self,
        voicemail_boxes_service: VoicemailBoxService,
        box_id: Annotated[UUID, Parameter(title="Box ID", description="The voicemail box.")],
    ) -> VoicemailUnreadCount:
        """Get unread message count for a voicemail box.

        Args:
            voicemail_boxes_service: Voicemail Box Service
            box_id: Voicemail Box ID

        Returns:
            VoicemailUnreadCount
        """
        await voicemail_boxes_service.get(box_id)
        count = await voicemail_boxes_service.get_unread_count(box_id)
        return VoicemailUnreadCount(voicemail_box_id=box_id, unread_count=count)
