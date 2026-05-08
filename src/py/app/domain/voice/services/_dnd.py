from __future__ import annotations

import logging
from uuid import UUID

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m

logger = logging.getLogger(__name__)


class DoNotDisturbService(service.SQLAlchemyAsyncRepositoryService[m.DoNotDisturb]):
    """Do Not Disturb Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.DoNotDisturb]):
        """Do Not Disturb Repository."""

        model_type = m.DoNotDisturb

    repository_type = Repo

    async def get_or_create_for_extension(self, extension_id: UUID) -> m.DoNotDisturb:
        db_obj = await self.get_one_or_none(extension_id=extension_id)
        if db_obj is not None:
            return db_obj
        try:
            return await self.create({"extension_id": extension_id})
        except Exception:
            logger.warning("Race condition creating DND record for extension %s, fetching existing", extension_id, exc_info=True)
            await self.repository.session.rollback()
            return await self.get_one(extension_id=extension_id)
