"""Fax Message Controllers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, post
from litestar.di import Provide
from litestar.exceptions import PermissionDeniedException
from litestar.params import Dependency, Parameter
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.fax.controllers._fax_number import _can_access_fax_number
from app.domain.fax.guards import requires_fax_message_access
from app.domain.teams.guards import requires_feature_permission
from app.db.models._fax_enums import FaxDirection, FaxStatus
from app.domain.fax.schemas import FaxMessage, SendFax
from app.domain.fax.services import FaxMessageService, FaxNumberService
from app.domain.notifications.deps import provide_notifications_service
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService
    from app.domain.notifications.services import NotificationService


class FaxMessageController(Controller):
    """Fax Messages."""

    tags = ["Fax Messages"]
    dependencies = create_service_dependencies(
        FaxMessageService,
        key="fax_messages_service",
        load=[selectinload(m.FaxMessage.fax_number)],
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
        FaxNumberService,
        key="fax_numbers_service",
        load=[selectinload(m.FaxNumber.email_routes)],
    ) | {
        "audit_service": Provide(provide_audit_log_service),
        "notifications_service": Provide(provide_notifications_service),
    }

    @get(
        component="fax/message-list",
        operation_id="ListFaxMessages",
        path="/api/fax/messages",
        guards=[requires_feature_permission("fax", "view")],
    )
    async def list_fax_messages(
        self,
        fax_messages_service: FaxMessageService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[FaxMessage]:
        """List fax messages the current user can access.

        Args:
            fax_messages_service: Fax Message Service
            current_user: Current User
            filters: Filters

        Returns:
            OffsetPagination[FaxMessage]
        """
        user_fax_ids = (
            select(m.FaxNumber.id)
            .where(
                (m.FaxNumber.user_id == current_user.id)
                | (
                    m.FaxNumber.team_id.in_(
                        select(m.TeamMember.team_id)
                        .where(m.TeamMember.user_id == current_user.id)
                        .scalar_subquery()
                    )
                )
            )
            .scalar_subquery()
        )
        results, total = await fax_messages_service.list_and_count(
            *filters,
            m.FaxMessage.fax_number_id.in_(user_fax_ids),
        )
        return fax_messages_service.to_schema(results, total, filters, schema_type=FaxMessage)

    @get(
        operation_id="GetFaxMessage",
        path="/api/fax/messages/{message_id:uuid}",
        guards=[requires_feature_permission("fax", "view"), requires_fax_message_access],
    )
    async def get_fax_message(
        self,
        fax_messages_service: FaxMessageService,
        current_user: m.User,
        message_id: Annotated[UUID, Parameter(title="Message ID", description="The fax message to retrieve.")],
    ) -> FaxMessage:
        """Get details about a fax message.

        Args:
            fax_messages_service: Fax Message Service
            current_user: Current User
            message_id: Message ID

        Raises:
            PermissionDeniedException: If user cannot access this fax message

        Returns:
            FaxMessage
        """
        db_obj = await fax_messages_service.get(message_id)
        if not _can_access_fax_number(current_user, db_obj.fax_number):
            raise PermissionDeniedException(detail="Insufficient permissions to access this fax message.")
        return fax_messages_service.to_schema(db_obj, schema_type=FaxMessage)

    @delete(
        operation_id="DeleteFaxMessage",
        path="/api/fax/messages/{message_id:uuid}",
        guards=[requires_feature_permission("fax", "edit"), requires_fax_message_access],
    )
    async def delete_fax_message(
        self,
        request: Request[m.User, Token, Any],
        fax_messages_service: FaxMessageService,
        audit_service: AuditLogService,
        current_user: m.User,
        message_id: Annotated[UUID, Parameter(title="Message ID", description="The fax message to delete.")],
    ) -> None:
        """Delete a fax message.

        Args:
            request: The current request
            fax_messages_service: Fax Message Service
            audit_service: Audit Log Service
            current_user: Current User
            message_id: Message ID

        Raises:
            PermissionDeniedException: If user cannot access this fax message
        """
        db_obj = await fax_messages_service.get(message_id)
        if not _can_access_fax_number(current_user, db_obj.fax_number):
            raise PermissionDeniedException(detail="Insufficient permissions to access this fax message.")
        before = capture_snapshot(db_obj)
        await fax_messages_service.delete(message_id)
        await log_audit(
            audit_service,
            action="fax.message_delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="fax_message",
            target_id=message_id,
            target_label=str(message_id),
            before=before,
            after=None,
            request=request,
        )

    @post(
        operation_id="SendFax",
        path="/api/fax/send",
        guards=[requires_feature_permission("fax", "edit")],
    )
    async def send_fax(
        self,
        request: Request[m.User, Token, Any],
        data: SendFax,
        fax_messages_service: FaxMessageService,
        fax_numbers_service: FaxNumberService,
        audit_service: AuditLogService,
        notifications_service: NotificationService,
        current_user: m.User,
    ) -> FaxMessage:
        fax_number = await fax_numbers_service.get(data.fax_number_id)
        if not _can_access_fax_number(current_user, fax_number):
            raise PermissionDeniedException(detail="Insufficient permissions to send from this fax number.")
        db_obj = await fax_messages_service.create(
            {
                "fax_number_id": data.fax_number_id,
                "direction": FaxDirection.OUTBOUND,
                "remote_number": data.destination_number,
                "remote_name": data.subject,
                "status": FaxStatus.QUEUED,
                "page_count": 0,
                "file_path": "",
                "file_size_bytes": 0,
                "received_at": datetime.now(tz=timezone.utc),
            }
        )
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="fax.send",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="fax_message",
            target_id=db_obj.id,
            target_label=data.destination_number,
            before=None,
            after=after,
            request=request,
        )
        try:
            await notifications_service.notify(
                user_id=current_user.id,
                title="Fax Queued",
                message=f"Your fax to {data.destination_number} has been queued for delivery.",
                category="fax",
                action_url="/fax/messages",
            )
        except Exception:
            pass
        return fax_messages_service.to_schema(db_obj, schema_type=FaxMessage)
