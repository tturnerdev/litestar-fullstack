from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class PhoneNumberService(service.SQLAlchemyAsyncRepositoryService[m.PhoneNumber]):
    """Phone Number Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.PhoneNumber]):
        """Phone Number Repository."""

        model_type = m.PhoneNumber

    repository_type = Repo
