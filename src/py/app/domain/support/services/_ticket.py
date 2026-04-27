from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m
from app.lib.deps import CompositeServiceMixin

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT


class TicketService(CompositeServiceMixin, service.SQLAlchemyAsyncRepositoryService[m.Ticket]):
    """Handles CRUD operations on Ticket resources."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.Ticket]):
        """Ticket Repository."""

        model_type = m.Ticket

    repository_type = Repo
    match_fields = ["ticket_number"]

    async def to_model_on_create(self, data: ModelDictT[m.Ticket]) -> ModelDictT[m.Ticket]:
        data = service.schema_dump(data)
        if service.is_dict(data) and "ticket_number" not in data:
            data["ticket_number"] = await self._generate_ticket_number()
        return data

    async def _generate_ticket_number(self) -> str:
        """Generate a sequential ticket number like SUP-00001."""
        count = await self.count()
        return f"SUP-{count + 1:05d}"

    async def close_ticket(self, ticket_id: Any) -> m.Ticket:
        """Close a ticket by setting status and closed_at."""
        now = datetime.now(UTC)
        return await self.update(
            {"status": m.TicketStatus.CLOSED, "closed_at": now},
            item_id=ticket_id,
        )

    async def reopen_ticket(self, ticket_id: Any) -> m.Ticket:
        """Reopen a closed ticket."""
        return await self.update(
            {"status": m.TicketStatus.OPEN, "closed_at": None, "resolved_at": None},
            item_id=ticket_id,
        )
