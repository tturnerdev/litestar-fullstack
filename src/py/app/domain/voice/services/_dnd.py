from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class DoNotDisturbService(service.SQLAlchemyAsyncRepositoryService[m.DoNotDisturb]):
    """Do Not Disturb Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.DoNotDisturb]):
        """Do Not Disturb Repository."""

        model_type = m.DoNotDisturb

    repository_type = Repo
