from __future__ import annotations

from typing import TYPE_CHECKING

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m
from app.domain.support.utils import render_markdown

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT


class TicketMessageService(service.SQLAlchemyAsyncRepositoryService[m.TicketMessage]):
    """Handles CRUD operations on TicketMessage resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.TicketMessage]):
        """TicketMessage Repository."""

        model_type = m.TicketMessage

    repository_type = Repo

    async def to_model_on_create(self, data: ModelDictT[m.TicketMessage]) -> ModelDictT[m.TicketMessage]:
        data = service.schema_dump(data)
        if service.is_dict(data) and "body_markdown" in data:
            data["body_html"] = render_markdown(data["body_markdown"])
        return data

    async def to_model_on_update(self, data: ModelDictT[m.TicketMessage]) -> ModelDictT[m.TicketMessage]:
        data = service.schema_dump(data)
        if service.is_dict(data) and "body_markdown" in data:
            data["body_html"] = render_markdown(data["body_markdown"])
        return data
