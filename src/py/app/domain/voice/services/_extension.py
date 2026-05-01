from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class ExtensionService(service.SQLAlchemyAsyncRepositoryService[m.Extension]):
    """Extension Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.Extension]):
        """Extension Repository."""

        model_type = m.Extension

    repository_type = Repo

    async def get_by_extension_number(self, extension_number: str) -> m.Extension | None:
        """Look up an extension by its extension number.

        Args:
            extension_number: The extension number to search for.

        Returns:
            The matching Extension model instance, or ``None`` if not found.
        """
        results, _ = await self.list_and_count(m.Extension.extension_number == extension_number)
        return results[0] if results else None
