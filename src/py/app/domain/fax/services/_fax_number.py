from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class FaxNumberService(service.SQLAlchemyAsyncRepositoryService[m.FaxNumber]):
    """Handles CRUD operations on FaxNumber resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.FaxNumber]):
        """FaxNumber Repository."""

        model_type = m.FaxNumber

    repository_type = Repo
    match_fields = ["number"]
