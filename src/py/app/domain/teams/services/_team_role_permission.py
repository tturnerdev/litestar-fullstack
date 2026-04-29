from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class TeamRolePermissionService(service.SQLAlchemyAsyncRepositoryService[m.TeamRolePermission]):
    """Team Role Permission Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.TeamRolePermission]):
        """Team Role Permission Repository."""

        model_type = m.TeamRolePermission

    repository_type = Repo
