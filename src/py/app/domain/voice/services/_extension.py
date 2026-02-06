from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class ExtensionService(service.SQLAlchemyAsyncRepositoryService[m.Extension]):
    """Extension Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.Extension]):
        """Extension Repository."""

        model_type = m.Extension

    repository_type = Repo
