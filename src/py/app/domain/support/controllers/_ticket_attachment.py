"""Ticket Attachment Controllers."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from litestar import Controller, delete, get, post
from litestar.params import Parameter

from app.db import models as m
from app.domain.support.guards import requires_ticket_access
from app.domain.support.schemas import TicketAttachment
from app.domain.support.services import TicketAttachmentService
from app.lib.deps import create_service_dependencies


class TicketAttachmentController(Controller):
    """Ticket Attachments."""

    tags = ["Support"]
    dependencies = create_service_dependencies(
        TicketAttachmentService,
        key="attachments_service",
    )

    @post(
        operation_id="UploadAttachment",
        path="/api/support/tickets/{ticket_id:uuid}/attachments",
        guards=[requires_ticket_access],
    )
    async def upload_attachment(
        self,
        attachments_service: TicketAttachmentService,
        current_user: m.User,
        ticket_id: Annotated[UUID, Parameter(title="Ticket ID")],
    ) -> TicketAttachment:
        """Upload file(s) for a ticket.

        Note: Full multipart upload will be implemented in Phase 3.
        This is a placeholder endpoint.
        """
        _ = ticket_id
        _ = current_user
        _ = attachments_service
        msg = "File upload not yet implemented. Coming in Phase 3."
        raise NotImplementedError(msg)

    @get(operation_id="GetAttachment", path="/api/support/attachments/{attachment_id:uuid}")
    async def get_attachment(
        self,
        attachments_service: TicketAttachmentService,
        attachment_id: Annotated[UUID, Parameter(title="Attachment ID", description="The attachment to retrieve.")],
    ) -> TicketAttachment:
        """Download/view attachment."""
        db_obj = await attachments_service.get(attachment_id)
        return attachments_service.to_schema(db_obj, schema_type=TicketAttachment)

    @delete(operation_id="DeleteAttachment", path="/api/support/attachments/{attachment_id:uuid}")
    async def delete_attachment(
        self,
        attachments_service: TicketAttachmentService,
        attachment_id: Annotated[UUID, Parameter(title="Attachment ID", description="The attachment to delete.")],
    ) -> None:
        """Delete an attachment."""
        _ = await attachments_service.delete(attachment_id)

    @post(
        operation_id="PasteImage",
        path="/api/support/tickets/{ticket_id:uuid}/paste-image",
        guards=[requires_ticket_access],
    )
    async def paste_image(
        self,
        attachments_service: TicketAttachmentService,
        current_user: m.User,
        ticket_id: Annotated[UUID, Parameter(title="Ticket ID")],
    ) -> TicketAttachment:
        """Upload a clipboard-pasted image.

        Note: Full paste-image handling will be implemented in Phase 3.
        This is a placeholder endpoint.
        """
        _ = ticket_id
        _ = current_user
        _ = attachments_service
        msg = "Paste image not yet implemented. Coming in Phase 3."
        raise NotImplementedError(msg)
