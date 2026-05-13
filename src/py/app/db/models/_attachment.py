"""Attachment model - user-uploaded files backed by object storage."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from advanced_alchemy.types import StoredObject
from advanced_alchemy.types.file_object import (
    FileObject,  # noqa: TC002  (needed at runtime by SQLAlchemy for Mapped[FileObject])
)
from sqlalchemy import BigInteger, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.lib.settings import get_settings

if TYPE_CHECKING:
    from app.db.models._team import Team
    from app.db.models._user import User


class AttachmentPurpose(StrEnum):
    """What an uploaded file is used for."""

    ATTACHMENT = "attachment"
    AVATAR = "avatar"
    TEAM_LOGO = "team_logo"
    IMPORT = "import"
    OTHER = "other"


class Attachment(UUIDv7AuditBase):
    """A file uploaded by a user and stored in object storage.

    Only metadata (filename, size, content type, checksum, backend key) lives in
    the database - the bytes live in the object store, referenced by the
    :attr:`file` column.
    """

    __tablename__ = "attachment"
    __table_args__ = {"comment": "User-uploaded files stored in object storage"}

    uploaded_by_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("user_account.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    """The user who uploaded the file (null if the user was deleted)."""
    team_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("team.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    """The team the attachment belongs to, if any."""
    file: Mapped[FileObject] = mapped_column(StoredObject(backend=get_settings().storage.REGISTRY_KEY))
    """The stored file (metadata; bytes are in the object store)."""
    original_filename: Mapped[str] = mapped_column(String(length=255))
    """Filename as provided by the client."""
    content_type: Mapped[str] = mapped_column(String(length=255))
    """MIME type of the file."""
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    """File size in bytes."""
    checksum_sha256: Mapped[str | None] = mapped_column(String(length=64), nullable=True)
    """Hex-encoded SHA-256 digest of the file contents."""
    purpose: Mapped[AttachmentPurpose] = mapped_column(
        String(length=32),
        default=AttachmentPurpose.ATTACHMENT,
        nullable=False,
        index=True,
    )
    """What the file is used for."""

    uploaded_by: Mapped[User | None] = relationship(lazy="joined", foreign_keys=[uploaded_by_id])
    team: Mapped[Team | None] = relationship(lazy="joined", foreign_keys=[team_id])
