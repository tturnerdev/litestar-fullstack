"""Voicemail message service."""

from __future__ import annotations

from uuid import UUID

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class VoicemailMessageService(service.SQLAlchemyAsyncRepositoryService[m.VoicemailMessage]):
    """Handles CRUD operations on VoicemailMessage resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.VoicemailMessage]):
        """VoicemailMessage Repository."""

        model_type = m.VoicemailMessage

    repository_type = Repo

    async def mark_read(self, message_id: UUID) -> m.VoicemailMessage:
        """Mark a voicemail message as read.

        Args:
            message_id: VoicemailMessage ID

        Returns:
            Updated VoicemailMessage
        """
        return await self.update(item_id=message_id, data={"is_read": True})

    async def mark_unread(self, message_id: UUID) -> m.VoicemailMessage:
        """Mark a voicemail message as unread.

        Args:
            message_id: VoicemailMessage ID

        Returns:
            Updated VoicemailMessage
        """
        return await self.update(item_id=message_id, data={"is_read": False})
