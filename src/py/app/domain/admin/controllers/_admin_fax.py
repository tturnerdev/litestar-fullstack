"""Admin Fax Controller."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from advanced_alchemy.service.pagination import OffsetPagination
from litestar import Controller, get
from litestar.di import Provide
from litestar.params import Dependency

from app.db import models as m
from app.domain.accounts.guards import requires_superuser
from app.domain.admin.schemas import AdminFaxMessageSummary, AdminFaxNumberSummary, AdminFaxStats
from app.domain.fax.deps import provide_fax_messages_service, provide_fax_numbers_service
from app.domain.fax.services import FaxMessageService, FaxNumberService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes


class AdminFaxController(Controller):
    tags = ["Admin"]
    path = "/api/admin/fax"
    guards = [requires_superuser]
    dependencies = create_service_dependencies(
        FaxNumberService,
        key="fax_number_service",
        filters={
            "id_filter": UUID,
            "search": "number,label",
            "pagination_type": "limit_offset",
            "pagination_size": 25,
            "created_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    ) | {
        "fax_message_service": Provide(provide_fax_messages_service),
    }

    @get(operation_id="AdminListFaxNumbers", path="/numbers")
    async def list_fax_numbers(
        self,
        fax_number_service: FaxNumberService,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[AdminFaxNumberSummary]:
        results, total = await fax_number_service.list_and_count(*filters)
        limit_offset = next((f for f in filters if hasattr(f, "limit")), None)
        items = [
            AdminFaxNumberSummary(
                id=fn.id,
                number=fn.number,
                label=fn.label,
                is_active=fn.is_active,
                owner_email=fn.user.email if fn.user else None,
                team_name=fn.team.name if fn.team else None,
                created_at=fn.created_at,
            )
            for fn in results
        ]
        return OffsetPagination(
            items=items,
            total=total,
            limit=limit_offset.limit if limit_offset else 25,
            offset=limit_offset.offset if limit_offset else 0,
        )

    @get(operation_id="AdminListFaxMessages", path="/messages")
    async def list_fax_messages(
        self,
        fax_message_service: FaxMessageService,
    ) -> list[AdminFaxMessageSummary]:
        results = await fax_message_service.list(
            order_by=[m.FaxMessage.received_at.desc()],
            limit=50,
        )
        return [
            AdminFaxMessageSummary(
                id=msg.id,
                fax_number=msg.fax_number.number if msg.fax_number else "Unknown",
                direction=msg.direction,
                remote_number=msg.remote_number,
                remote_name=msg.remote_name,
                page_count=msg.page_count,
                status=msg.status,
                error_message=msg.error_message,
                received_at=msg.received_at,
                created_at=msg.created_at,
            )
            for msg in results
        ]

    @get(operation_id="AdminGetFaxStats", path="/stats")
    async def get_stats(
        self,
        fax_number_service: FaxNumberService,
        fax_message_service: FaxMessageService,
    ) -> AdminFaxStats:
        now = datetime.now(UTC)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        total_numbers = await fax_number_service.count()
        active_numbers = await fax_number_service.count(m.FaxNumber.is_active.is_(True))
        total_messages = await fax_message_service.count()
        messages_today = await fax_message_service.count(m.FaxMessage.received_at >= today_start)
        inbound_today = await fax_message_service.count(
            m.FaxMessage.received_at >= today_start,
            m.FaxMessage.direction == "inbound",
        )
        outbound_today = await fax_message_service.count(
            m.FaxMessage.received_at >= today_start,
            m.FaxMessage.direction == "outbound",
        )
        failed_today = await fax_message_service.count(
            m.FaxMessage.received_at >= today_start,
            m.FaxMessage.status == "failed",
        )

        return AdminFaxStats(
            total_numbers=total_numbers,
            active_numbers=active_numbers,
            total_messages=total_messages,
            messages_today=messages_today,
            inbound_today=inbound_today,
            outbound_today=outbound_today,
            failed_today=failed_today,
        )
