"""Music on Hold service."""

from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class MusicOnHoldService(service.SQLAlchemyAsyncRepositoryService[m.MusicOnHold]):
    """Handles CRUD operations on MusicOnHold resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.MusicOnHold]):
        """MusicOnHold Repository."""

        model_type = m.MusicOnHold

    repository_type = Repo
    match_fields = ["name"]

    async def get_default(self) -> m.MusicOnHold | None:
        """Get the default Music on Hold class.

        Returns:
            The default MusicOnHold or None if no default is set.
        """
        results = await self.list(
            m.MusicOnHold.is_default.is_(True),
            m.MusicOnHold.is_active.is_(True),
        )
        return results[0] if results else None
