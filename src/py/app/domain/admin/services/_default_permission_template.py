"""Default Permission Template Service."""

from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class DefaultPermissionTemplateService(service.SQLAlchemyAsyncRepositoryService[m.DefaultPermissionTemplate]):
    """Default Permission Template Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.DefaultPermissionTemplate]):
        """Default Permission Template Repository."""

        model_type = m.DefaultPermissionTemplate

    repository_type = Repo
    match_fields = ["role", "feature_area"]
