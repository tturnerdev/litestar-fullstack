"""Time condition service."""

from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class TimeConditionService(service.SQLAlchemyAsyncRepositoryService[m.TimeCondition]):
    """Handles CRUD operations on TimeCondition resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.TimeCondition]):
        """TimeCondition Repository."""

        model_type = m.TimeCondition

    repository_type = Repo
    match_fields = ["name"]
