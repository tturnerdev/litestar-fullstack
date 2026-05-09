"""Ticket Message Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.support.guards import requires_ticket_access, requires_ticket_message_edit
from app.domain.support.schemas import TicketMessage, TicketMessageCreate
from app.domain.support.services import TicketMessageService
from app.domain.teams.guards import requires_feature_permission
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class TicketMessageController(Controller):
    """Ticket Messages."""

    tags = ["Ticket Messages"]
    dependencies = create_service_dependencies(
        TicketMessageService,
        key="messages_service",
        load=[selectinload(m.TicketMessage.author), selectinload(m.TicketMessage.attachments)],
        filters={
            "id_filter": UUID,
            "pagination_type": "limit_offset",
            "pagination_size": 50,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "asc",
            "search": "body_markdown",
        },
    ) | {
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(
        operation_id="ListTicketMessages",
        summary="List ticket messages",
        description="Returns a paginated list of messages for a ticket, sorted by creation date ascending. Internal notes are hidden from non-superusers. Supports search by message body and date range filtering.",
        path="/api/support/tickets/{ticket_id:uuid}/messages",
        guards=[requires_feature_permission("support", "view"), requires_ticket_access],
    )
    async def list_messages(
        self,
        messages_service: TicketMessageService,
        current_user: m.User,
        ticket_id: Annotated[UUID, Parameter(title="Ticket ID")],
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[TicketMessage]:
        """List messages in a ticket."""
        # Filter out internal notes for non-superusers
        if current_user.is_superuser:
            results, total = await messages_service.list_and_count(
                *filters,
                m.TicketMessage.ticket_id == ticket_id,
            )
        else:
            results, total = await messages_service.list_and_count(
                *filters,
                m.TicketMessage.ticket_id == ticket_id,
                m.TicketMessage.is_internal_note == False,  # noqa: E712
            )
        return messages_service.to_schema(results, total, filters, schema_type=TicketMessage)

    @post(
        operation_id="CreateTicketMessage",
        summary="Create a ticket message",
        description="Adds a new reply to a ticket thread. Emits a ticket_message_created event and records an audit log entry with the message snapshot.",
        path="/api/support/tickets/{ticket_id:uuid}/messages",
        guards=[requires_feature_permission("support", "edit"), requires_ticket_access],
        status_code=HTTP_201_CREATED,
    )
    async def create_message(
        self,
        request: Request[m.User, Token, Any],
        messages_service: TicketMessageService,
        audit_service: AuditLogService,
        current_user: m.User,
        ticket_id: Annotated[UUID, Parameter(title="Ticket ID")],
        data: TicketMessageCreate,
    ) -> TicketMessage:
        """Add a reply to a ticket."""
        obj = data.to_dict()
        obj["ticket_id"] = ticket_id
        obj["author_id"] = current_user.id
        db_obj = await messages_service.create(obj)
        request.app.emit(event_id="ticket_message_created", ticket_id=ticket_id, message_id=db_obj.id)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="support.message_create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ticket_message",
            target_id=db_obj.id,
            target_label=f"ticket:{ticket_id}",
            before=None,
            after=after,
            request=request,
        )
        return messages_service.to_schema(db_obj, schema_type=TicketMessage)

    @patch(
        operation_id="UpdateTicketMessage",
        summary="Update a ticket message",
        description="Edits an existing ticket message. Only the original author may edit, and the edit window is enforced by the requires_ticket_message_edit guard. Emits a ticket_message_updated event and records an audit log entry.",
        path="/api/support/tickets/{ticket_id:uuid}/messages/{msg_id:uuid}",
        guards=[requires_feature_permission("support", "edit"), requires_ticket_access, requires_ticket_message_edit],
    )
    async def update_message(
        self,
        request: Request[m.User, Token, Any],
        messages_service: TicketMessageService,
        audit_service: AuditLogService,
        current_user: m.User,
        ticket_id: Annotated[UUID, Parameter(title="Ticket ID")],
        msg_id: Annotated[UUID, Parameter(title="Message ID", description="The message to update.")],
        data: TicketMessageCreate,
    ) -> TicketMessage:
        """Edit a message (own, within time window)."""
        before = capture_snapshot(await messages_service.get(msg_id))
        db_obj = await messages_service.update(
            item_id=msg_id,
            data=data.to_dict(),
        )
        request.app.emit(event_id="ticket_message_updated", ticket_id=ticket_id, message_id=msg_id)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="support.message_update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ticket_message",
            target_id=msg_id,
            target_label=f"ticket:{ticket_id}",
            before=before,
            after=after,
            request=request,
        )
        return messages_service.to_schema(db_obj, schema_type=TicketMessage)

    @delete(
        operation_id="DeleteTicketMessage",
        summary="Delete a ticket message",
        description="Permanently deletes a ticket message. Only the original author may delete within the allowed edit window. Emits a ticket_message_deleted event and records an audit log entry.",
        path="/api/support/tickets/{ticket_id:uuid}/messages/{msg_id:uuid}",
        guards=[requires_feature_permission("support", "edit"), requires_ticket_access, requires_ticket_message_edit],
        status_code=HTTP_204_NO_CONTENT,
        return_dto=None,
    )
    async def delete_message(
        self,
        request: Request[m.User, Token, Any],
        messages_service: TicketMessageService,
        audit_service: AuditLogService,
        current_user: m.User,
        ticket_id: Annotated[UUID, Parameter(title="Ticket ID")],
        msg_id: Annotated[UUID, Parameter(title="Message ID", description="The message to delete.")],
    ) -> None:
        """Delete a message (own, within time window)."""
        db_obj = await messages_service.get(msg_id)
        before = capture_snapshot(db_obj)
        request.app.emit(event_id="ticket_message_deleted", message_id=msg_id)
        await messages_service.delete(msg_id)
        await log_audit(
            audit_service,
            action="support.message_delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ticket_message",
            target_id=msg_id,
            target_label=f"ticket:{ticket_id}",
            before=before,
            after=None,
            request=request,
        )
