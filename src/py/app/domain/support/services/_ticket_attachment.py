from __future__ import annotations

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m


class TicketAttachmentService(service.SQLAlchemyAsyncRepositoryService[m.TicketAttachment]):
    """Handles CRUD operations on TicketAttachment resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.TicketAttachment]):
        """TicketAttachment Repository."""

        model_type = m.TicketAttachment

    repository_type = Repo
