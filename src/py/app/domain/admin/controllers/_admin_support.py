"""Admin Support Controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from advanced_alchemy.service.pagination import OffsetPagination
from litestar import Controller, get
from litestar.params import Dependency

from app.db import models as m
from app.domain.accounts.guards import requires_superuser
from app.domain.admin.schemas import AdminSupportStats, AdminTicketSummary
from app.domain.support.services import TicketService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes


class AdminSupportController(Controller):
    tags = ["Admin"]
    path = "/api/admin/support"
    guards = [requires_superuser]
    dependencies = create_service_dependencies(
        TicketService,
        key="ticket_service",
        filters={
            "id_filter": UUID,
            "search": "ticket_number,subject",
            "pagination_type": "limit_offset",
            "pagination_size": 25,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    )

    @get(operation_id="AdminListTickets", path="/tickets")
    async def list_tickets(
        self,
        ticket_service: TicketService,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[AdminTicketSummary]:
        results, total = await ticket_service.list_and_count(*filters)
        limit_offset = next((f for f in filters if hasattr(f, "limit")), None)
        items = [
            AdminTicketSummary(
                id=t.id,
                ticket_number=t.ticket_number,
                subject=t.subject,
                status=t.status,
                priority=t.priority,
                category=t.category,
                is_read_by_agent=t.is_read_by_agent,
                creator_email=t.user.email if t.user else None,
                assigned_to_email=t.assigned_to.email if t.assigned_to else None,
                created_at=t.created_at,
                updated_at=t.updated_at,
                closed_at=t.closed_at,
            )
            for t in results
        ]
        return OffsetPagination(
            items=items,
            total=total,
            limit=limit_offset.limit if limit_offset else 25,
            offset=limit_offset.offset if limit_offset else 0,
        )

    @get(operation_id="AdminGetSupportStats", path="/stats")
    async def get_stats(
        self,
        ticket_service: TicketService,
    ) -> AdminSupportStats:
        total = await ticket_service.count()
        open_count = await ticket_service.count(m.Ticket.status == "open")
        in_progress = await ticket_service.count(m.Ticket.status == "in_progress")
        waiting_customer = await ticket_service.count(m.Ticket.status == "waiting_on_customer")
        waiting_support = await ticket_service.count(m.Ticket.status == "waiting_on_support")
        resolved = await ticket_service.count(m.Ticket.status == "resolved")
        closed = await ticket_service.count(m.Ticket.status == "closed")

        all_tickets = await ticket_service.list()
        priority_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        for t in all_tickets:
            priority_counts[t.priority] = priority_counts.get(t.priority, 0) + 1
            cat = t.category or "uncategorized"
            category_counts[cat] = category_counts.get(cat, 0) + 1

        return AdminSupportStats(
            total=total,
            open=open_count,
            in_progress=in_progress,
            waiting_on_customer=waiting_customer,
            waiting_on_support=waiting_support,
            resolved=resolved,
            closed=closed,
            by_priority=priority_counts,
            by_category=category_counts,
        )
