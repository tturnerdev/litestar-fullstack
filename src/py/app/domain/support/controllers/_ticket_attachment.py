"""Ticket Attachment Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, post
from litestar.di import Provide
from litestar.params import Parameter

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.support.guards import requires_ticket_access
from app.domain.support.schemas import TicketAttachment
from app.domain.support.services import TicketAttachmentService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class TicketAttachmentController(Controller):
    """Ticket Attachments."""

    tags = ["Support"]
    dependencies = create_service_dependencies(
        TicketAttachmentService,
        key="attachments_service",
    ) | {
        "audit_service": Provide(provide_audit_log_service),
    }

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
        request: Request[m.User, Token, Any],
        attachments_service: TicketAttachmentService,
        audit_service: AuditLogService,
        current_user: m.User,
        attachment_id: Annotated[UUID, Parameter(title="Attachment ID", description="The attachment to delete.")],
    ) -> None:
        """Delete an attachment."""
        db_obj = await attachments_service.get(attachment_id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.file_name
        await attachments_service.delete(attachment_id)
        await log_audit(
            audit_service,
            action="support.attachment_delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ticket_attachment",
            target_id=attachment_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )

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
