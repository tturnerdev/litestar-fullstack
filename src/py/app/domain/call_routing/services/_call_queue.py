"""Call queue service."""

from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class CallQueueService(service.SQLAlchemyAsyncRepositoryService[m.CallQueue]):
    """Handles CRUD operations on CallQueue resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.CallQueue]):
        """CallQueue Repository."""

        model_type = m.CallQueue

    repository_type = Repo
    match_fields = ["name"]


class CallQueueMemberService(service.SQLAlchemyAsyncRepositoryService[m.CallQueueMember]):
    """Handles CRUD operations on CallQueueMember resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.CallQueueMember]):
        """CallQueueMember Repository."""

        model_type = m.CallQueueMember

    repository_type = Repo
