from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class ForwardingRuleService(service.SQLAlchemyAsyncRepositoryService[m.ForwardingRule]):
    """Forwarding Rule Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.ForwardingRule]):
        """Forwarding Rule Repository."""

        model_type = m.ForwardingRule

    repository_type = Repo
