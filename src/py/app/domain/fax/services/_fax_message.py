from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class FaxMessageService(service.SQLAlchemyAsyncRepositoryService[m.FaxMessage]):
    """Handles CRUD operations on FaxMessage resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.FaxMessage]):
        """FaxMessage Repository."""

        model_type = m.FaxMessage

    repository_type = Repo
