"""Attachment service - manages uploaded files and their object-storage backing."""

from __future__ import annotations

import datetime
import hashlib
import re
from typing import TYPE_CHECKING

import structlog
from advanced_alchemy import repository, service
from advanced_alchemy.types.file_object import FileObject, storages
from litestar.exceptions import ClientException, TooManyRequestsException
from sqlalchemy import func, select

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

    async def _enforce_upload_quotas(self, size: int, uploaded_by_id: UUID | None, team_id: UUID | None) -> None:
        storage = get_settings().storage
        session = self.repository.session
        if storage.MAX_UPLOADS_PER_HOUR and uploaded_by_id is not None:
            since = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)
            recent = await session.scalar(
                select(func.count())
                .select_from(m.Attachment)
                .where(m.Attachment.uploaded_by_id == uploaded_by_id, m.Attachment.created_at >= since)
            )
            if (recent or 0) >= storage.MAX_UPLOADS_PER_HOUR:
                msg = "Upload rate limit exceeded. Try again later."
                raise TooManyRequestsException(detail=msg)
        if storage.TEAM_QUOTA_BYTES and team_id is not None:
            used = await session.scalar(
                select(func.coalesce(func.sum(m.Attachment.size_bytes), 0)).where(m.Attachment.team_id == team_id)
            )
            if (used or 0) + size > storage.TEAM_QUOTA_BYTES:
                msg = "This team has reached its storage quota."
                raise ClientException(detail=msg, status_code=413)

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
            ClientException: If the file is empty, exceeds the size limit, or the team quota is exceeded.
            TooManyRequestsException: If the per-user upload rate limit is exceeded.

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
            raise ClientException(detail=msg, status_code=413)
        await self._enforce_upload_quotas(len(data), uploaded_by_id, team_id)
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

    async def presign_upload(
        self,
        *,
        original_filename: str,
        purpose: m.AttachmentPurpose,
    ) -> tuple[str, str, int]:
        """Generate a presigned ``PUT`` URL for direct-to-storage uploads.

        Args:
            original_filename: Client-supplied filename (used to build the object path).
            purpose: The attachment purpose (used as a path prefix).

        Raises:
            ClientException: If the configured storage backend does not support presigning.

        Returns:
            A ``(path, presigned_url, expires_in_seconds)`` tuple.
        """
        from uuid_utils import uuid7

        storage = get_settings().storage
        backend = storages.get_backend(storage.REGISTRY_KEY)
        safe_name = _sanitize_filename(original_filename)
        path = f"{purpose.value}/{uuid7()}-{safe_name}"
        try:
            url = await backend.sign_async(path, expires_in=storage.PRESIGN_EXPIRY, for_upload=True)
        except (NotImplementedError, AttributeError) as exc:
            msg = "The configured storage backend does not support presigned uploads."
            raise ClientException(detail=msg) from exc
        return path, str(url), storage.PRESIGN_EXPIRY

    async def complete_upload(
        self,
        *,
        path: str,
        original_filename: str,
        content_type: str,
        purpose: m.AttachmentPurpose,
        uploaded_by_id: UUID | None,
        team_id: UUID | None,
    ) -> m.Attachment:
        """Finalize a presigned upload: verify the object exists, record an attachment row.

        Args:
            path: The object-storage path previously handed to the client.
            original_filename: Display filename to record.
            content_type: MIME type.
            purpose: Attachment purpose.
            uploaded_by_id: The uploading user, if any.
            team_id: The owning team, if any.

        Raises:
            ClientException: If the object is not found at ``path`` or exceeds the size limit.

        Returns:
            The persisted attachment.
        """
        import contextlib

        import obstore

        storage = get_settings().storage
        backend = storages.get_backend(storage.REGISTRY_KEY)
        try:
            meta = await obstore.head_async(backend.fs, path)
        except Exception as exc:
            msg = "Uploaded object was not found at the presigned path."
            raise ClientException(detail=msg) from exc
        size = int(meta["size"])
        if size > storage.MAX_UPLOAD_BYTES:
            with contextlib.suppress(Exception):
                backend.delete_object(path)
            msg = f"Uploaded file exceeds the maximum size of {storage.MAX_UPLOAD_BYTES} bytes."
            raise ClientException(detail=msg, status_code=413)
        await self._enforce_upload_quotas(size, uploaded_by_id, team_id)
        file_object = FileObject(
            backend=storage.REGISTRY_KEY,
            filename=path,
            content_type=content_type,
            size=size,
        )
        return await self.create(
            m.Attachment(
                file=file_object,
                original_filename=_sanitize_filename(original_filename),
                content_type=content_type,
                size_bytes=size,
                checksum_sha256=None,
                purpose=purpose,
                uploaded_by_id=uploaded_by_id,
                team_id=team_id,
            ),
        )

    async def cleanup_orphan_objects(self) -> dict[str, int]:
        """Remove objects in the bucket that no attachment row references.

        Objects newer than ``STORAGE_ORPHAN_GC_GRACE_SECONDS`` are skipped so
        in-flight uploads are never collected.

        Returns:
            Counts of objects scanned, kept, and deleted.
        """
        import obstore

        storage = get_settings().storage
        backend = storages.get_backend(storage.REGISTRY_KEY)
        known_paths = {
            fo.path
            for fo in (await self.repository.session.scalars(select(m.Attachment.file))).all()
            if fo is not None and fo.path
        }
        cutoff = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=storage.ORPHAN_GC_GRACE_SECONDS)
        scanned = kept = deleted = 0
        for batch in obstore.list(backend.fs):
            for meta in batch:
                scanned += 1
                path = meta["path"]
                last_modified = meta.get("last_modified")
                if path in known_paths or (last_modified is not None and last_modified > cutoff):
                    kept += 1
                    continue
                try:
                    backend.delete_object(path)
                    deleted += 1
                except Exception as exc:  # noqa: BLE001 - best-effort
                    kept += 1
                    logger.warning("failed to delete orphan object", path=path, error=str(exc))
        return {"scanned": scanned, "kept": kept, "deleted": deleted}
