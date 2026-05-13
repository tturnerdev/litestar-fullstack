"""Attachment service - manages uploaded files and their object-storage backing."""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING

import structlog
from advanced_alchemy import repository, service
from advanced_alchemy.types.file_object import FileObject
from litestar.exceptions import ClientException

from app.db import models as m
from app.lib.settings import get_settings

if TYPE_CHECKING:
    from uuid import UUID

    from litestar.datastructures import UploadFile

__all__ = ("AttachmentService",)

logger = structlog.get_logger()

_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")
_DEFAULT_CONTENT_TYPE = "application/octet-stream"


def _sanitize_filename(filename: str | None) -> str:
    """Reduce a client-supplied filename to a safe, path-component-free string."""
    name = (filename or "file").rsplit("/", 1)[-1].rsplit("\\", 1)[-1].strip()
    name = _UNSAFE_FILENAME_CHARS.sub("-", name).strip("-.")
    return name or "file"


class AttachmentService(service.SQLAlchemyAsyncRepositoryService[m.Attachment]):
    """Handles attachments stored in object storage."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.Attachment]):
        """Attachment repository."""

        model_type = m.Attachment

    repository_type = Repo

    async def create_from_upload(
        self,
        upload: UploadFile,
        *,
        uploaded_by_id: UUID | None = None,
        team_id: UUID | None = None,
        purpose: m.AttachmentPurpose = m.AttachmentPurpose.ATTACHMENT,
    ) -> m.Attachment:
        """Validate an uploaded file, store its bytes, and persist its metadata.

        Args:
            upload: The multipart file upload.
            uploaded_by_id: The id of the uploading user, if known.
            team_id: The owning team id, if any.
            purpose: What the file is used for.

        Raises:
            ClientException: If the file is empty or exceeds the configured size limit.

        Returns:
            The persisted attachment.
        """
        storage = get_settings().storage
        data = await upload.read()
        if not data:
            msg = "Uploaded file is empty."
            raise ClientException(detail=msg)
        if len(data) > storage.MAX_UPLOAD_BYTES:
            msg = f"File exceeds the maximum upload size of {storage.MAX_UPLOAD_BYTES} bytes."
            raise ClientException(detail=msg)
        checksum = hashlib.sha256(data).hexdigest()
        content_type = upload.content_type or _DEFAULT_CONTENT_TYPE
        safe_name = _sanitize_filename(upload.filename)
        file_object = FileObject(
            backend=storage.REGISTRY_KEY,
            filename=f"{purpose.value}/{checksum[:2]}/{checksum}-{safe_name}",
            content_type=content_type,
            content=data,
        )
        stored = await file_object.save_async()
        return await self.create(
            m.Attachment(
                file=stored,
                original_filename=safe_name,
                content_type=content_type,
                size_bytes=len(data),
                checksum_sha256=checksum,
                purpose=purpose,
                uploaded_by_id=uploaded_by_id,
                team_id=team_id,
            ),
        )

    async def delete_with_object(self, attachment: m.Attachment) -> m.Attachment:
        """Delete an attachment row and best-effort remove its stored object.

        Args:
            attachment: The attachment to delete.

        Returns:
            The deleted attachment.
        """
        try:
            await attachment.file.delete_async()
        except Exception as exc:  # noqa: BLE001 - object removal is best-effort
            logger.warning("failed to delete stored object", attachment_id=str(attachment.id), error=str(exc))
        return await self.delete(attachment.id)

    @staticmethod
    async def get_content(attachment: m.Attachment) -> bytes:
        """Return the raw bytes of a stored attachment."""
        return await attachment.file.get_content_async()
