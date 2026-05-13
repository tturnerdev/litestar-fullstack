"""Admin Attachments Controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, cast
from uuid import UUID

from litestar import Controller, delete, get
from litestar.params import Dependency, Parameter

from app.domain.accounts.guards import requires_superuser
from app.domain.admin.deps import provide_audit_log_service
from app.domain.admin.schemas import AdminAttachment
from app.domain.attachments.services import AttachmentService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.extensions.litestar.providers import FilterConfig
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination

    from app.db import models as m
    from app.domain.admin.services import AuditLogService


class AdminAttachmentsController(Controller):
    """Admin attachments endpoints."""

    tags = ["Admin"]
    path = "/api/admin/attachments"
    guards = [requires_superuser]
    dependencies = {
        **create_service_dependencies(
            AttachmentService,
            key="attachments_service",
            filters=cast(
                "FilterConfig",
                {
                    "id_filter": UUID,
                    "search": "original_filename,content_type",
                    "in_fields": {"purpose", "uploaded_by_id", "team_id"},
                    "pagination_type": "limit_offset",
                    "pagination_size": 50,
                    "created_at": True,
                    "sort_field": "created_at",
                    "sort_order": "desc",
                },
            ),
        ),
        "audit_service": provide_audit_log_service,
    }

    @get(operation_id="AdminListAttachments")
    async def list_attachments(
        self,
        attachments_service: AttachmentService,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[AdminAttachment]:
        """List every attachment in the system."""
        results, total = await attachments_service.list_and_count(*filters)
        return attachments_service.to_schema(results, total, filters, schema_type=AdminAttachment)

    @delete(
        operation_id="AdminDeleteAttachment",
        path="/{attachment_id:uuid}",
        return_dto=None,
    )
    async def delete_attachment(
        self,
        attachments_service: AttachmentService,
        audit_service: AuditLogService,
        current_user: m.User,
        attachment_id: Annotated[UUID, Parameter(title="Attachment ID")],
    ) -> None:
        """Delete an attachment (row + stored object) and record an audit entry."""
        attachment = await attachments_service.get(attachment_id)
        await attachments_service.delete_with_object(attachment)
        await audit_service.log_action(
            "attachment.deleted",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="attachment",
            target_id=str(attachment_id),
            target_label=attachment.original_filename,
        )
