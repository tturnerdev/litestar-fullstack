"""Attachment service - manages uploaded files and their object-storage backing."""

from __future__ import annotations

import contextlib
import datetime
import hashlib
import re
from typing import TYPE_CHECKING

import obstore
import structlog
from advanced_alchemy import repository, service
from advanced_alchemy.types.file_object import FileObject, storages
from litestar.exceptions import ClientException, TooManyRequestsException
from sqlalchemy import func, select, update
from uuid_utils import uuid7

from app.db import models as m
from app.lib.settings import get_settings

if TYPE_CHECKING:
    from uuid import UUID

    from litestar.datastructures import UploadFile

__all__ = ("RESTRICTED_PURPOSES", "AttachmentService")

logger = structlog.get_logger()

_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")
_DEFAULT_CONTENT_TYPE = "application/octet-stream"
_MAX_FILENAME_LENGTH = 200
# Purposes that may only be uploaded through their dedicated endpoints
# (``PUT /api/me/avatar``, ``PUT /api/teams/{id}/logo``). Letting them flow
# through the generic /api/uploads or /api/uploads/{presign,complete} paths
# would let any user create rows tagged as someone else's avatar / a team logo.
RESTRICTED_PURPOSES: frozenset[m.AttachmentPurpose] = frozenset(
    {m.AttachmentPurpose.AVATAR, m.AttachmentPurpose.TEAM_LOGO}
)


def _sanitize_filename(filename: str | None) -> str:
    """Reduce a client-supplied filename to a safe, path-component-free string."""
    name = (filename or "file").rsplit("/", 1)[-1].rsplit("\\", 1)[-1].strip()
    name = _UNSAFE_FILENAME_CHARS.sub("-", name).strip("-.")
    name = name[:_MAX_FILENAME_LENGTH]
    return name or "file"


class AttachmentService(service.SQLAlchemyAsyncRepositoryService[m.Attachment]):
    """Handles attachments stored in object storage."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.Attachment]):
        """Attachment repository."""

        model_type = m.Attachment

    repository_type = Repo

    async def _enforce_upload_quotas(
        self,
        size: int,
        uploaded_by_id: UUID | None,
        team_id: UUID | None,
        *,
        excluding_attachment_id: UUID | None = None,
    ) -> None:
        """Reject the in-flight upload if it would breach the configured limits.

        Note that these checks are best-effort under READ COMMITTED isolation:
        concurrent uploads from the same user / team can both see the
        pre-burst totals and pass. Treat the limits as soft caps; pair with
        an external rate limiter for harder guarantees.
        """
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
            stmt = select(func.coalesce(func.sum(m.Attachment.size_bytes), 0)).where(m.Attachment.team_id == team_id)
            if excluding_attachment_id is not None:
                stmt = stmt.where(m.Attachment.id != excluding_attachment_id)
            used = await session.scalar(stmt)
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
        excluding_attachment_id: UUID | None = None,
    ) -> m.Attachment:
        """Validate an uploaded file, store its bytes, and persist its metadata.

        Args:
            upload: The multipart file upload.
            uploaded_by_id: The id of the uploading user, if known.
            team_id: The owning team id, if any.
            purpose: What the file is used for.
            excluding_attachment_id: When replacing an existing attachment (avatar/logo),
                exclude its bytes from the team quota calculation so a same-size
                replacement at the cap does not spuriously 413.

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
        await self._enforce_upload_quotas(
            len(data),
            uploaded_by_id,
            team_id,
            excluding_attachment_id=excluding_attachment_id,
        )
        checksum = hashlib.sha256(data).hexdigest()
        content_type = upload.content_type or _DEFAULT_CONTENT_TYPE
        safe_name = _sanitize_filename(upload.filename)
        # Server-chosen path namespaced by uploader to prevent another user
        # from claiming this object via the /complete endpoint.
        owner_segment = str(uploaded_by_id) if uploaded_by_id is not None else "_anon"
        file_object = FileObject(
            backend=storage.REGISTRY_KEY,
            filename=f"{purpose.value}/{owner_segment}/{uuid7()}-{safe_name}",
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
        """Delete an attachment row, null any owner ``*_url`` fields, and remove the stored object.

        Order matters: we null the row + the dangling display URLs *first* (so a
        crash here leaves no broken ``avatar_url``/``logo_url`` pointing at a
        404), then best-effort remove the stored object. If the storage delete
        fails, the orphan-GC job will pick it up later.
        """
        session = self.repository.session
        # The FK is ON DELETE SET NULL, but the display-URL columns (avatar_url,
        # logo_url) are plain strings — null them explicitly so they stay in
        # sync after the cascade nulls the *_id columns.
        await session.execute(update(m.User).where(m.User.avatar_id == attachment.id).values(avatar_url=None))
        await session.execute(update(m.Team).where(m.Team.logo_id == attachment.id).values(logo_url=None))
        deleted = await self.delete(attachment.id)
        try:
            await attachment.file.delete_async()
        except Exception as exc:  # noqa: BLE001 - object removal is best-effort
            logger.warning("failed to delete stored object", attachment_id=str(attachment.id), error=str(exc))
        return deleted

    @staticmethod
    async def get_content(attachment: m.Attachment) -> bytes:
        """Return the raw bytes of a stored attachment."""
        return await attachment.file.get_content_async()

    async def presign_upload(
        self,
        *,
        uploaded_by_id: UUID,
        original_filename: str,
        purpose: m.AttachmentPurpose,
    ) -> tuple[str, str, int]:
        """Generate a presigned ``PUT`` URL for direct-to-storage uploads.

        The returned ``path`` is namespaced by ``uploaded_by_id`` so a different
        user cannot finalize an attachment over the same path via /complete.

        Args:
            uploaded_by_id: The user the presigned URL is issued to.
            original_filename: Client-supplied filename (used to build the object path).
            purpose: The attachment purpose. AVATAR / TEAM_LOGO are rejected here —
                use the dedicated avatar / team-logo endpoints instead.

        Raises:
            ClientException: If the purpose is restricted, or the configured
                storage backend does not support presigning.

        Returns:
            A ``(path, presigned_url, expires_in_seconds)`` tuple.
        """
        if purpose in RESTRICTED_PURPOSES:
            msg = "Avatars and team logos must be uploaded through their dedicated endpoints."
            raise ClientException(detail=msg)
        storage = get_settings().storage
        backend = storages.get_backend(storage.REGISTRY_KEY)
        safe_name = _sanitize_filename(original_filename)
        path = f"{purpose.value}/{uploaded_by_id}/{uuid7()}-{safe_name}"
        try:
            url = await backend.sign_async(path, expires_in=storage.PRESIGN_EXPIRY, for_upload=True)
        except (NotImplementedError, AttributeError, ValueError) as exc:
            logger.warning("presign failed", path=path, error=str(exc))
            msg = "The configured storage backend does not support presigned uploads."
            raise ClientException(detail=msg) from exc
        return path, str(url), storage.PRESIGN_EXPIRY

    async def complete_upload(
        self,
        *,
        uploaded_by_id: UUID,
        path: str,
        original_filename: str,
        content_type: str,
        purpose: m.AttachmentPurpose,
        team_id: UUID | None,
    ) -> m.Attachment:
        """Finalize a presigned upload: verify the object exists, record an attachment row.

        Args:
            uploaded_by_id: The user finalizing the upload. The path must lie
                under this user's namespace.
            path: The object-storage path previously handed to the client.
            original_filename: Display filename to record.
            content_type: MIME type.
            purpose: Attachment purpose. AVATAR / TEAM_LOGO are rejected here.
            team_id: The owning team, if any. Membership must be validated by the caller.

        Raises:
            ClientException: If the purpose is restricted, the path is not under
                the caller's namespace, the object is not found, or the size
                exceeds the configured limit.

        Returns:
            The persisted attachment.
        """
        if purpose in RESTRICTED_PURPOSES:
            msg = "Avatars and team logos must be uploaded through their dedicated endpoints."
            raise ClientException(detail=msg)
        expected_prefix = f"{purpose.value}/{uploaded_by_id}/"
        # reject ``..`` traversal and any path not under the caller's namespace
        if ".." in path or path.startswith("/") or not path.startswith(expected_prefix):
            msg = "Invalid upload path."
            raise ClientException(detail=msg)
        storage = get_settings().storage
        backend = storages.get_backend(storage.REGISTRY_KEY)
        try:
            meta = await obstore.head_async(backend.fs, path)
        except Exception as exc:
            logger.warning("complete_upload: head failed", path=path, error=str(exc))
            msg = "Uploaded object was not found at the presigned path."
            raise ClientException(detail=msg) from exc
        size = int(meta["size"])
        if size > storage.MAX_UPLOAD_BYTES:
            with contextlib.suppress(Exception):
                await backend.delete_object_async(path)
            msg = f"Uploaded file exceeds the maximum size of {storage.MAX_UPLOAD_BYTES} bytes."
            raise ClientException(detail=msg, status_code=413)
        try:
            await self._enforce_upload_quotas(size, uploaded_by_id, team_id)
        except (ClientException, TooManyRequestsException):
            # The object is already in the bucket — clean it up so a rejected
            # /complete does not leave bytes behind we can't tie a row to until
            # the next GC sweep.
            with contextlib.suppress(Exception):
                await backend.delete_object_async(path)
            raise
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
        storage = get_settings().storage
        backend = storages.get_backend(storage.REGISTRY_KEY)
        known_paths = {
            fo.path
            for fo in (await self.repository.session.scalars(select(m.Attachment.file))).all()
            if fo is not None and fo.path
        }
        cutoff = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=storage.ORPHAN_GC_GRACE_SECONDS)
        scanned = kept = deleted = 0
        async for batch in obstore.list(backend.fs):
            for meta in batch:
                scanned += 1
                path = meta["path"]
                last_modified = meta.get("last_modified")
                if path in known_paths or (last_modified is not None and last_modified > cutoff):
                    kept += 1
                    continue
                try:
                    await backend.delete_object_async(path)
                    deleted += 1
                except Exception as exc:  # noqa: BLE001 - best-effort
                    kept += 1
                    logger.warning("failed to delete orphan object", path=path, error=str(exc))
        return {"scanned": scanned, "kept": kept, "deleted": deleted}
