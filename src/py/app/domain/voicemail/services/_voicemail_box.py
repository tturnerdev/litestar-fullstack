"""Voicemail box service."""

from __future__ import annotations

from uuid import UUID

from advanced_alchemy.extensions.litestar import repository, service
from sqlalchemy import func, select

from app.db import models as m


class VoicemailBoxService(service.SQLAlchemyAsyncRepositoryService[m.VoicemailBox]):
    """Handles CRUD operations on VoicemailBox resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.VoicemailBox]):
        """VoicemailBox Repository."""

        model_type = m.VoicemailBox

    repository_type = Repo

    async def get_or_create_for_extension(self, extension_id: UUID) -> m.VoicemailBox:
        """Get or create a voicemail box for the given extension.

        Args:
            extension_id: Extension ID

        Returns:
            VoicemailBox
        """
        db_obj = await self.get_one_or_none(extension_id=extension_id)
        if db_obj is not None:
            return db_obj
        try:
            return await self.create({"extension_id": extension_id})
        except Exception:
            await self.repository.session.rollback()
            return await self.get_one(extension_id=extension_id)

    async def get_unread_count(self, box_id: UUID) -> int:
        """Get unread message count for a voicemail box.

        Args:
            box_id: VoicemailBox ID

        Returns:
            Number of unread messages
        """
        result = await self.repository.session.execute(
            select(func.count(m.VoicemailMessage.id)).where(
                m.VoicemailMessage.voicemail_box_id == box_id,
                m.VoicemailMessage.is_read == False,  # noqa: E712
            )
        )
        return result.scalar_one()
