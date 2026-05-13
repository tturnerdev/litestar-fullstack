"""Attachment (file upload) controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from litestar import Controller, Response, delete, get, post
from litestar.datastructures import (
    UploadFile,  # noqa: TC002  (resolved at runtime by Litestar for the request signature)
)
from litestar.enums import RequestEncodingType
from litestar.exceptions import ClientException, PermissionDeniedException
from litestar.params import Body, Dependency, Parameter

from app.db import models as m
from app.domain.accounts.guards import requires_active_user
from app.domain.admin.deps import provide_audit_log_service
from app.domain.attachments.schemas import (
    Attachment,
    CompleteUploadRequest,
    PresignRequest,
    PresignResponse,
)
from app.domain.attachments.services import AttachmentService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination

    from app.domain.admin.services import AuditLogService


# Purposes whose content is intended to be displayed inline (e.g. as an
# ``<img src>``) and is therefore readable to any authenticated user.
_PUBLIC_VIEW_PURPOSES: frozenset[m.AttachmentPurpose] = frozenset(
    {m.AttachmentPurpose.AVATAR, m.AttachmentPurpose.TEAM_LOGO}
)

# Image content types we will serve inline for ``_PUBLIC_VIEW_PURPOSES`` content.
# Anything else (HTML, SVG, JS, arbitrary documents) is forced to download as
# ``application/octet-stream`` to prevent stored-XSS / content-sniffing
# attacks against the application origin.
_SAFE_INLINE_CONTENT_TYPES: frozenset[str] = frozenset(
    {"image/png", "image/jpeg", "image/jpg", "image/gif", "image/webp"}
)


def _content_url(attachment_id: UUID) -> str:
    return f"/api/uploads/{attachment_id}/content"


def _assert_access(attachment: m.Attachment, user: m.User) -> None:
    """Authorization for read access to a stored attachment.

    Avatars and team logos are visible to any authenticated user — they are
    displayed inline in the UI and gating them per-uploader is impractical.
    All other purposes are restricted to the uploader or a superuser.
    """
    if user.is_superuser or attachment.uploaded_by_id == user.id:
        return
    if attachment.purpose in _PUBLIC_VIEW_PURPOSES:
        return
    raise PermissionDeniedException(detail="You do not have access to this attachment.")


def _safe_download_response(content: bytes, attachment: m.Attachment) -> Response[bytes]:
    """Return a response for streamed attachment bytes with appropriate hardening.

    For attachments whose purpose is inline-display (avatars, team logos), we
    allow the recorded content-type only if it is in a safe image whitelist;
    everything else is forced to ``application/octet-stream`` with
    ``Content-Disposition: attachment``. ``X-Content-Type-Options: nosniff`` is
    always set so browsers do not promote a downloaded blob to HTML.
    """
    if attachment.purpose in _PUBLIC_VIEW_PURPOSES and attachment.content_type in _SAFE_INLINE_CONTENT_TYPES:
        media_type = attachment.content_type
        disposition = f'inline; filename="{attachment.original_filename}"'
    else:
        media_type = "application/octet-stream"
        disposition = f'attachment; filename="{attachment.original_filename}"'
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "content-disposition": disposition,
            "x-content-type-options": "nosniff",
        },
    )


def _user_is_team_member(user: m.User, team_id: UUID) -> bool:
    return user.is_superuser or any(membership.team.id == team_id for membership in user.teams)


class AttachmentController(Controller):
    """File uploads."""

    tags = ["Uploads"]
    path = "/api/uploads"
    guards = [requires_active_user]
    dependencies = {
        **create_service_dependencies(
            AttachmentService,
            key="attachments_service",
            filters={
                "id_filter": UUID,
                "pagination_type": "limit_offset",
                "pagination_size": 20,
                "created_at": True,
                "sort_field": "created_at",
                "sort_order": "desc",
            },
        ),
        "audit_service": provide_audit_log_service,
    }

    @get(operation_id="ListUploads")
    async def list_uploads(
        self,
        attachments_service: AttachmentService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[Attachment]:
        """List the current user's uploads (all uploads for superusers)."""
        if current_user.is_superuser:
            results, total = await attachments_service.list_and_count(*filters)
        else:
            results, total = await attachments_service.list_and_count(*filters, uploaded_by_id=current_user.id)
        page = attachments_service.to_schema(results, total, filters, schema_type=Attachment)
        for item in page.items:
            item.download_url = _content_url(item.id)
        return page

    @post(operation_id="UploadFile")
    async def upload_file(
        self,
        attachments_service: AttachmentService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: Annotated[UploadFile, Body(media_type=RequestEncodingType.MULTI_PART)],
        purpose: m.AttachmentPurpose = m.AttachmentPurpose.ATTACHMENT,
    ) -> Attachment:
        """Upload a file and store it in object storage."""
        from app.domain.attachments.services._attachment import RESTRICTED_PURPOSES

        if purpose in RESTRICTED_PURPOSES:
            msg = "Avatars and team logos must be uploaded through their dedicated endpoints."
            raise ClientException(detail=msg)
        db_obj = await attachments_service.create_from_upload(
            data,
            uploaded_by_id=current_user.id,
            purpose=purpose,
        )
        await audit_service.log_action(
            "attachment.uploaded",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="attachment",
            target_id=str(db_obj.id),
            target_label=db_obj.original_filename,
            details={"size_bytes": db_obj.size_bytes, "content_type": db_obj.content_type, "purpose": purpose.value},
        )
        schema = attachments_service.to_schema(db_obj, schema_type=Attachment)
        schema.download_url = _content_url(schema.id)
        return schema

    @post(operation_id="PresignUpload", path="/presign")
    async def presign_upload(
        self,
        attachments_service: AttachmentService,
        current_user: m.User,
        data: PresignRequest,
    ) -> PresignResponse:
        """Get a presigned ``PUT`` URL the client can upload directly to.

        After uploading, the client must call ``POST /api/uploads/complete``
        with the returned ``path`` to record an attachment row.
        """
        try:
            purpose = m.AttachmentPurpose(data.purpose)
        except ValueError as exc:
            msg = f"Unknown purpose: {data.purpose!r}"
            raise ClientException(detail=msg) from exc
        path, url, expires_in = await attachments_service.presign_upload(
            uploaded_by_id=current_user.id,
            original_filename=data.filename,
            purpose=purpose,
        )
        return PresignResponse(upload_url=url, path=path, expires_in=expires_in)

    @post(operation_id="CompleteUpload", path="/complete")
    async def complete_upload(
        self,
        attachments_service: AttachmentService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: CompleteUploadRequest,
    ) -> Attachment:
        """Finalize a presigned upload by recording metadata for the just-PUT object."""
        try:
            purpose = m.AttachmentPurpose(data.purpose)
        except ValueError as exc:
            msg = f"Unknown purpose: {data.purpose!r}"
            raise ClientException(detail=msg) from exc
        if data.team_id is not None and not _user_is_team_member(current_user, data.team_id):
            raise PermissionDeniedException(detail="You are not a member of that team.")
        db_obj = await attachments_service.complete_upload(
            uploaded_by_id=current_user.id,
            path=data.path,
            original_filename=data.original_filename,
            content_type=data.content_type,
            purpose=purpose,
            team_id=data.team_id,
        )
        await audit_service.log_action(
            "attachment.uploaded",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="attachment",
            target_id=str(db_obj.id),
            target_label=db_obj.original_filename,
            details={
                "size_bytes": db_obj.size_bytes,
                "content_type": db_obj.content_type,
                "purpose": purpose.value,
                "presigned": True,
            },
        )
        schema = attachments_service.to_schema(db_obj, schema_type=Attachment)
        schema.download_url = _content_url(schema.id)
        return schema

    @get(operation_id="GetUpload", path="/{attachment_id:uuid}")
    async def get_upload(
        self,
        attachments_service: AttachmentService,
        current_user: m.User,
        attachment_id: Annotated[UUID, Parameter(title="Attachment ID", description="The attachment to retrieve.")],
    ) -> Attachment:
        """Get metadata for an uploaded file."""
        db_obj = await attachments_service.get(attachment_id)
        _assert_access(db_obj, current_user)
        schema = attachments_service.to_schema(db_obj, schema_type=Attachment)
        schema.download_url = _content_url(schema.id)
        return schema

    @get(operation_id="DownloadUpload", path="/{attachment_id:uuid}/content", media_type="application/octet-stream")
    async def download_upload(
        self,
        attachments_service: AttachmentService,
        current_user: m.User,
        attachment_id: Annotated[UUID, Parameter(title="Attachment ID", description="The attachment to download.")],
    ) -> Response[bytes]:
        """Stream the raw bytes of an uploaded file.

        For attachment-purpose downloads (and any non-image content) the
        response is forced to ``application/octet-stream`` with
        ``Content-Disposition: attachment`` to prevent stored-XSS via uploaded
        HTML/SVG/JS. Avatars and team logos with a whitelisted image content
        type are served inline so the browser can render them.
        """
        db_obj = await attachments_service.get(attachment_id)
        _assert_access(db_obj, current_user)
        content = await AttachmentService.get_content(db_obj)
        return _safe_download_response(content, db_obj)

    @delete(operation_id="DeleteUpload", path="/{attachment_id:uuid}", return_dto=None)
    async def delete_upload(
        self,
        attachments_service: AttachmentService,
        audit_service: AuditLogService,
        current_user: m.User,
        attachment_id: Annotated[UUID, Parameter(title="Attachment ID", description="The attachment to delete.")],
    ) -> None:
        """Delete an uploaded file and its stored object."""
        db_obj = await attachments_service.get(attachment_id)
        _assert_access(db_obj, current_user)
        await attachments_service.delete_with_object(db_obj)
        await audit_service.log_action(
            "attachment.deleted",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="attachment",
            target_id=str(attachment_id),
            target_label=db_obj.original_filename,
        )
