"""Ticket Message Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.params import Dependency, Parameter
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.support.guards import requires_ticket_access, requires_ticket_message_edit
from app.domain.support.schemas import TicketMessage, TicketMessageCreate
from app.domain.support.services import TicketMessageService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination


class TicketMessageController(Controller):
    """Ticket Messages."""

    tags = ["Support"]
    guards = [requires_ticket_access]
    dependencies = create_service_dependencies(
        TicketMessageService,
        key="messages_service",
        load=[selectinload(m.TicketMessage.author), selectinload(m.TicketMessage.attachments)],
        filters={
            "id_filter": UUID,
            "pagination_type": "limit_offset",
            "pagination_size": 50,
            "created_at": True,
            "sort_field": "created_at",
            "sort_order": "asc",
        },
    )

    @get(operation_id="ListTicketMessages", path="/api/support/tickets/{ticket_id:uuid}/messages")
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

    @post(operation_id="CreateTicketMessage", path="/api/support/tickets/{ticket_id:uuid}/messages")
    async def create_message(
        self,
        messages_service: TicketMessageService,
        current_user: m.User,
        ticket_id: Annotated[UUID, Parameter(title="Ticket ID")],
        data: TicketMessageCreate,
    ) -> TicketMessage:
        """Add a reply to a ticket."""
        obj = data.to_dict()
        obj["ticket_id"] = ticket_id
        obj["author_id"] = current_user.id
        db_obj = await messages_service.create(obj)
        return messages_service.to_schema(db_obj, schema_type=TicketMessage)

    @patch(
        operation_id="UpdateTicketMessage",
        path="/api/support/tickets/{ticket_id:uuid}/messages/{msg_id:uuid}",
        guards=[requires_ticket_message_edit],
    )
    async def update_message(
        self,
        messages_service: TicketMessageService,
        ticket_id: Annotated[UUID, Parameter(title="Ticket ID")],
        msg_id: Annotated[UUID, Parameter(title="Message ID", description="The message to update.")],
        data: TicketMessageCreate,
    ) -> TicketMessage:
        """Edit a message (own, within time window)."""
        db_obj = await messages_service.update(
            item_id=msg_id,
            data=data.to_dict(),
        )
        return messages_service.to_schema(db_obj, schema_type=TicketMessage)

    @delete(
        operation_id="DeleteTicketMessage",
        path="/api/support/tickets/{ticket_id:uuid}/messages/{msg_id:uuid}",
        guards=[requires_ticket_message_edit],
    )
    async def delete_message(
        self,
        messages_service: TicketMessageService,
        ticket_id: Annotated[UUID, Parameter(title="Ticket ID")],
        msg_id: Annotated[UUID, Parameter(title="Message ID", description="The message to delete.")],
    ) -> None:
        """Delete a message (own, within time window)."""
        _ = await messages_service.delete(msg_id)
