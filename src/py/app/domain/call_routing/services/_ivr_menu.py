"""IVR menu service."""

from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class IvrMenuService(service.SQLAlchemyAsyncRepositoryService[m.IvrMenu]):
    """Handles CRUD operations on IvrMenu resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.IvrMenu]):
        """IvrMenu Repository."""

        model_type = m.IvrMenu

    repository_type = Repo
    match_fields = ["name"]


class IvrMenuOptionService(service.SQLAlchemyAsyncRepositoryService[m.IvrMenuOption]):
    """Handles CRUD operations on IvrMenuOption resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.IvrMenuOption]):
        """IvrMenuOption Repository."""

        model_type = m.IvrMenuOption

    repository_type = Repo
