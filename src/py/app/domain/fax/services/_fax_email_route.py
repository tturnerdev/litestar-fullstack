from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class FaxEmailRouteService(service.SQLAlchemyAsyncRepositoryService[m.FaxEmailRoute]):
    """Handles CRUD operations on FaxEmailRoute resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.FaxEmailRoute]):
        """FaxEmailRoute Repository."""

        model_type = m.FaxEmailRoute

    repository_type = Repo
