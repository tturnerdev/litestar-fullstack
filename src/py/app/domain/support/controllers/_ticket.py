"""Ticket Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from litestar import Controller, get, patch, post
from litestar.params import Dependency, Parameter
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.support.guards import requires_support_agent, requires_ticket_access
from app.domain.support.schemas import Ticket, TicketCreate, TicketUpdate
from app.domain.support.services import TicketMessageService, TicketService
from app.domain.support.utils import render_markdown
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination


class TicketController(Controller):
    """Support Tickets."""

    tags = ["Support"]
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
    )

    @get(operation_id="ListTickets", path="/api/support/tickets")
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

    @post(operation_id="CreateTicket", path="/api/support/tickets")
    async def create_ticket(
        self,
        tickets_service: TicketService,
        current_user: m.User,
        data: TicketCreate,
    ) -> Ticket:
        """Open a new support ticket."""
        obj = data.to_dict()
        body_markdown = obj.pop("body_markdown")
        obj["user_id"] = current_user.id
        db_obj = await tickets_service.create(obj)
        # Create initial message
        msg_service = TicketMessageService(session=tickets_service.repository.session)
        await msg_service.create(
            {
                "ticket_id": db_obj.id,
                "author_id": current_user.id,
                "body_markdown": body_markdown,
                "body_html": render_markdown(body_markdown),
            }
        )
        return tickets_service.to_schema(db_obj, schema_type=Ticket)

    @get(
        operation_id="GetTicket",
        path="/api/support/tickets/{ticket_id:uuid}",
        guards=[requires_ticket_access],
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
        path="/api/support/tickets/{ticket_id:uuid}",
        guards=[requires_ticket_access],
    )
    async def update_ticket(
        self,
        data: TicketUpdate,
        tickets_service: TicketService,
        ticket_id: Annotated[UUID, Parameter(title="Ticket ID", description="The ticket to update.")],
    ) -> Ticket:
        """Update ticket (status, priority, assign)."""
        db_obj = await tickets_service.update(
            item_id=ticket_id,
            data=data.to_dict(),
        )
        return tickets_service.to_schema(db_obj, schema_type=Ticket)

    @post(
        operation_id="CloseTicket",
        path="/api/support/tickets/{ticket_id:uuid}/close",
        guards=[requires_ticket_access],
    )
    async def close_ticket(
        self,
        tickets_service: TicketService,
        ticket_id: Annotated[UUID, Parameter(title="Ticket ID", description="The ticket to close.")],
    ) -> Ticket:
        """Close a ticket."""
        db_obj = await tickets_service.close_ticket(ticket_id)
        return tickets_service.to_schema(db_obj, schema_type=Ticket)

    @post(
        operation_id="ReopenTicket",
        path="/api/support/tickets/{ticket_id:uuid}/reopen",
        guards=[requires_ticket_access],
    )
    async def reopen_ticket(
        self,
        tickets_service: TicketService,
        ticket_id: Annotated[UUID, Parameter(title="Ticket ID", description="The ticket to reopen.")],
    ) -> Ticket:
        """Reopen a closed ticket."""
        db_obj = await tickets_service.reopen_ticket(ticket_id)
        return tickets_service.to_schema(db_obj, schema_type=Ticket)
