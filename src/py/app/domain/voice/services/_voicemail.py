from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m

if TYPE_CHECKING:
    pass


class VoicemailBoxService(service.SQLAlchemyAsyncRepositoryService[m.VoicemailBox]):
    """Voicemail Box Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.VoicemailBox]):
        """Voicemail Box Repository."""

        model_type = m.VoicemailBox

    repository_type = Repo

    async def get_or_create_for_extension(self, extension_id: UUID) -> m.VoicemailBox:
        db_obj = await self.get_one_or_none(extension_id=extension_id)
        if db_obj is not None:
            return db_obj
        try:
            return await self.create({"extension_id": extension_id})
        except Exception:
            await self.repository.session.rollback()
            return await self.get_one(extension_id=extension_id)


class VoicemailMessageService(service.SQLAlchemyAsyncRepositoryService[m.VoicemailMessage]):
    """Voicemail Message Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.VoicemailMessage]):
        """Voicemail Message Repository."""

        model_type = m.VoicemailMessage

    repository_type = Repo
