"""Ring group service."""

from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class RingGroupService(service.SQLAlchemyAsyncRepositoryService[m.RingGroup]):
    """Handles CRUD operations on RingGroup resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.RingGroup]):
        """RingGroup Repository."""

        model_type = m.RingGroup

    repository_type = Repo
    match_fields = ["name"]


class RingGroupMemberService(service.SQLAlchemyAsyncRepositoryService[m.RingGroupMember]):
    """Handles CRUD operations on RingGroupMember resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.RingGroupMember]):
        """RingGroupMember Repository."""

        model_type = m.RingGroupMember

    repository_type = Repo
