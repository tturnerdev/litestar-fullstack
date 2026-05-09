"""Ticket Controllers."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.exceptions import PermissionDeniedException
from litestar.params import Dependency, Parameter
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.notifications.deps import provide_notifications_service
from app.domain.support.guards import requires_support_agent, requires_ticket_access
from app.domain.support.schemas import Ticket, TicketCreate, TicketUpdate
from app.domain.support.services import TicketMessageService, TicketService
from app.domain.support.utils import render_markdown
from app.domain.teams.guards import requires_feature_permission
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService
    from app.domain.notifications.services import NotificationService


class TicketController(Controller):
    """Support Tickets."""

    tags = ["Support Tickets"]
    dependencies = create_service_dependencies(
        TicketService,
        key="tickets_service",
        load=[selectinload(m.Ticket.user), selectinload(m.Ticket.assigned_to)],
        filters={
            "id_filter": UUID,
            "search": "subject",
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

    @get(
        operation_id="ListTickets",
        summary="List tickets",
        description="Returns a paginated list of support tickets. Superusers see all tickets; regular users only see their own. Supports search by subject, date range filtering, and configurable sort order.",
        path="/api/support/tickets",
        guards=[requires_feature_permission("support", "view")],
    )
    async def list_tickets(
        self,
        tickets_service: TicketService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[Ticket]:
        """List tickets accessible to the current user."""
        if current_user.is_superuser:
            results, total = await tickets_service.list_and_count(*filters)
        else:
            results, total = await tickets_service.list_and_count(
                *filters,
                m.Ticket.user_id == current_user.id,
            )
        return tickets_service.to_schema(results, total, filters, schema_type=Ticket)

    @post(
        operation_id="CreateTicket",
        summary="Create a ticket",
        description="Opens a new support ticket and creates the initial message from the provided markdown body. Emits a ticket_created event, records an audit log entry, and sends a notification to the submitting user.",
        path="/api/support/tickets",
        guards=[requires_feature_permission("support", "edit")],
        status_code=HTTP_201_CREATED,
    )
    async def create_ticket(
        self,
        request: Request[m.User, Token, Any],
        tickets_service: TicketService,
        audit_service: AuditLogService,
        notifications_service: NotificationService,
        current_user: m.User,
        data: TicketCreate,
    ) -> Ticket:
        """Open a new support ticket."""
        if data.team_id and not current_user.is_superuser and not any(tm.team_id == data.team_id for tm in current_user.teams):
            raise PermissionDeniedException(detail="You do not have access to this team")
        obj = data.to_dict()
        body_markdown = obj.pop("body_markdown")
        obj["user_id"] = current_user.id
        db_obj = await tickets_service.create(obj)
        request.app.emit(event_id="ticket_created", ticket_id=db_obj.id)
        # Create initial message
        msg_service = TicketMessageService(session=tickets_service.repository.session)
        initial_msg = await msg_service.create(
            {
                "ticket_id": db_obj.id,
                "author_id": current_user.id,
                "body_markdown": body_markdown,
                "body_html": render_markdown(body_markdown),
            }
        )
        request.app.emit(event_id="ticket_message_created", ticket_id=db_obj.id, message_id=initial_msg.id)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="support.ticket.created",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ticket",
            target_id=db_obj.id,
            target_label=db_obj.subject,
            before=None,
            after=after,
            request=request,
        )
        try:
            await notifications_service.notify(
                user_id=current_user.id,
                title="Ticket Created",
                message=f"Your support ticket '{db_obj.subject}' has been created.",
                category="ticket",
                action_url=f"/support/{db_obj.id}",
            )
        except Exception:
            logger.warning("Failed to send ticket creation notification", exc_info=True)
        return tickets_service.to_schema(db_obj, schema_type=Ticket)

    @get(
        operation_id="GetTicket",
        summary="Get ticket details",
        description="Retrieves a single support ticket by ID, including the associated user and assignee. Access is restricted to the ticket owner or a superuser.",
        path="/api/support/tickets/{ticket_id:uuid}",
        guards=[requires_feature_permission("support", "view"), requires_ticket_access],
    )
    async def get_ticket(
        self,
        tickets_service: TicketService,
        ticket_id: Annotated[UUID, Parameter(title="Ticket ID", description="The ticket to retrieve.")],
    ) -> Ticket:
        """Get ticket details."""
        db_obj = await tickets_service.get(ticket_id)
        return tickets_service.to_schema(db_obj, schema_type=Ticket)

    @patch(
        operation_id="UpdateTicket",
        summary="Update a ticket",
        description="Updates ticket fields such as status, priority, or assignee. Emits status change and assignment events when applicable, records an audit log entry, and notifies newly assigned agents.",
        path="/api/support/tickets/{ticket_id:uuid}",
        guards=[requires_feature_permission("support", "edit"), requires_ticket_access],
    )
    async def update_ticket(
        self,
        request: Request[m.User, Token, Any],
        data: TicketUpdate,
        tickets_service: TicketService,
        audit_service: AuditLogService,
        notifications_service: NotificationService,
        current_user: m.User,
        ticket_id: Annotated[UUID, Parameter(title="Ticket ID", description="The ticket to update.")],
    ) -> Ticket:
        """Update ticket (status, priority, assign)."""
        existing = await tickets_service.get(ticket_id)
        old_status = existing.status
        old_assigned_to_id = existing.assigned_to_id
        before = capture_snapshot(existing)
        db_obj = await tickets_service.update(
            item_id=ticket_id,
            data=data.to_dict(),
        )
        if db_obj.status != old_status:
            request.app.emit(
                event_id="ticket_status_changed",
                ticket_id=ticket_id,
                old_status=old_status,
                new_status=db_obj.status,
            )
        if db_obj.assigned_to_id is not None and db_obj.assigned_to_id != old_assigned_to_id:
            request.app.emit(
                event_id="ticket_assigned",
                ticket_id=ticket_id,
                assigned_to_id=db_obj.assigned_to_id,
            )
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="support.ticket.updated",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ticket",
            target_id=ticket_id,
            target_label=db_obj.subject,
            before=before,
            after=after,
            request=request,
        )
        if db_obj.assigned_to_id is not None and db_obj.assigned_to_id != old_assigned_to_id:
            try:
                await notifications_service.notify(
                    user_id=db_obj.assigned_to_id,
                    title="Ticket Assigned",
                    message=f"You have been assigned to support ticket '{db_obj.subject}'.",
                    category="ticket",
                    action_url=f"/support/{db_obj.id}",
                )
            except Exception:
                logger.warning("Failed to send ticket assignment notification", exc_info=True)
        return tickets_service.to_schema(db_obj, schema_type=Ticket)

    @delete(
        operation_id="DeleteTicket",
        summary="Delete a ticket",
        description="Permanently deletes a support ticket and all associated messages and attachments. Restricted to support agents. Emits a ticket_deleted event and records an audit log entry.",
        path="/api/support/tickets/{ticket_id:uuid}",
        guards=[requires_feature_permission("support", "edit"), requires_support_agent],
        status_code=HTTP_204_NO_CONTENT,
        return_dto=None,
    )
    async def delete_ticket(
        self,
        request: Request[m.User, Token, Any],
        tickets_service: TicketService,
        audit_service: AuditLogService,
        current_user: m.User,
        ticket_id: Annotated[UUID, Parameter(title="Ticket ID", description="The ticket to delete.")],
    ) -> None:
        """Delete a ticket and all associated messages/attachments."""
        db_obj = await tickets_service.get(ticket_id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.subject
        request.app.emit(event_id="ticket_deleted", ticket_id=ticket_id)
        await tickets_service.delete(ticket_id)
        await log_audit(
            audit_service,
            action="support.ticket.deleted",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ticket",
            target_id=ticket_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )

    @post(
        operation_id="CloseTicket",
        summary="Close a ticket",
        description="Transitions a ticket to the closed status. Emits a ticket_status_changed event, records an audit log entry, and sends a closure notification to the ticket owner.",
        path="/api/support/tickets/{ticket_id:uuid}/close",
        guards=[requires_feature_permission("support", "edit"), requires_ticket_access],
    )
    async def close_ticket(
        self,
        request: Request[m.User, Token, Any],
        tickets_service: TicketService,
        audit_service: AuditLogService,
        notifications_service: NotificationService,
        current_user: m.User,
        ticket_id: Annotated[UUID, Parameter(title="Ticket ID", description="The ticket to close.")],
    ) -> Ticket:
        """Close a ticket."""
        existing = await tickets_service.get(ticket_id)
        old_status = existing.status
        before = capture_snapshot(existing)
        db_obj = await tickets_service.close_ticket(ticket_id)
        request.app.emit(
            event_id="ticket_status_changed",
            ticket_id=ticket_id,
            old_status=old_status,
            new_status=db_obj.status,
        )
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="support.ticket.closed",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ticket",
            target_id=ticket_id,
            target_label=db_obj.subject,
            before=before,
            after=after,
            request=request,
        )
        try:
            await notifications_service.notify(
                user_id=db_obj.user_id,
                title="Ticket Closed",
                message=f"Your support ticket '{db_obj.subject}' has been closed.",
                category="ticket",
                action_url=f"/support/{db_obj.id}",
            )
        except Exception:
            logger.warning("Failed to send ticket closed notification", exc_info=True)
        return tickets_service.to_schema(db_obj, schema_type=Ticket)

    @post(
        operation_id="ReopenTicket",
        summary="Reopen a ticket",
        description="Reopens a previously closed ticket. Emits a ticket_status_changed event, records an audit log entry, and sends a reopened notification to the ticket owner.",
        path="/api/support/tickets/{ticket_id:uuid}/reopen",
        guards=[requires_feature_permission("support", "edit"), requires_ticket_access],
    )
    async def reopen_ticket(
        self,
        request: Request[m.User, Token, Any],
        tickets_service: TicketService,
        audit_service: AuditLogService,
        notifications_service: NotificationService,
        current_user: m.User,
        ticket_id: Annotated[UUID, Parameter(title="Ticket ID", description="The ticket to reopen.")],
    ) -> Ticket:
        """Reopen a closed ticket."""
        existing = await tickets_service.get(ticket_id)
        old_status = existing.status
        before = capture_snapshot(existing)
        db_obj = await tickets_service.reopen_ticket(ticket_id)
        request.app.emit(
            event_id="ticket_status_changed",
            ticket_id=ticket_id,
            old_status=old_status,
            new_status=db_obj.status,
        )
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="support.ticket.reopened",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ticket",
            target_id=ticket_id,
            target_label=db_obj.subject,
            before=before,
            after=after,
            request=request,
        )
        try:
            await notifications_service.notify(
                user_id=db_obj.user_id,
                title="Ticket Reopened",
                message=f"Your support ticket '{db_obj.subject}' has been reopened.",
                category="ticket",
                action_url=f"/support/{db_obj.id}",
            )
        except Exception:
            logger.warning("Failed to send ticket reopened notification", exc_info=True)
        return tickets_service.to_schema(db_obj, schema_type=Ticket)
