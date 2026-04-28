"""Organization service."""

from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m
from app.lib.service import AutoSlugServiceMixin


class OrganizationService(
    AutoSlugServiceMixin[m.Organization],
    service.SQLAlchemyAsyncRepositoryService[m.Organization],
):
    """Handles database operations for Organization resources."""

    class Repo(repository.SQLAlchemyAsyncSlugRepository[m.Organization]):
        """Organization Repository."""

        model_type = m.Organization

    repository_type = Repo
    match_fields = ["name"]
