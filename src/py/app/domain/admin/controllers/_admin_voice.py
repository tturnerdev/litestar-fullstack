"""Admin Voice Controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from advanced_alchemy.service.pagination import OffsetPagination
from litestar import Controller, get
from litestar.di import Provide
from litestar.params import Dependency

from app.db import models as m
from app.domain.accounts.guards import requires_superuser
from app.domain.admin.schemas import AdminExtensionSummary, AdminPhoneNumberSummary, AdminVoiceStats
from app.domain.voice.deps import provide_dnd_service, provide_extensions_service, provide_phone_numbers_service
from app.domain.voice.services import DoNotDisturbService, ExtensionService, PhoneNumberService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes


class AdminVoiceController(Controller):
    tags = ["Admin"]
    path = "/api/admin/voice"
    guards = [requires_superuser]
    dependencies = create_service_dependencies(
        PhoneNumberService,
        key="phone_number_service",
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
        "extension_service": Provide(provide_extensions_service),
        "dnd_service": Provide(provide_dnd_service),
    }

    @get(operation_id="AdminListPhoneNumbers", path="/phone-numbers")
    async def list_phone_numbers(
        self,
        phone_number_service: PhoneNumberService,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[AdminPhoneNumberSummary]:
        results, total = await phone_number_service.list_and_count(*filters)
        limit_offset = next((f for f in filters if hasattr(f, "limit")), None)
        items = [
            AdminPhoneNumberSummary(
                id=pn.id,
                number=pn.number,
                label=pn.label,
                number_type=pn.number_type,
                is_active=pn.is_active,
                caller_id_name=pn.caller_id_name,
                owner_email=pn.user.email if pn.user else None,
                team_name=pn.team.name if pn.team else None,
                created_at=pn.created_at,
            )
            for pn in results
        ]
        return OffsetPagination(
            items=items,
            total=total,
            limit=limit_offset.limit if limit_offset else 25,
            offset=limit_offset.offset if limit_offset else 0,
        )

    @get(operation_id="AdminListExtensions", path="/extensions")
    async def list_extensions(
        self,
        extension_service: ExtensionService,
    ) -> list[AdminExtensionSummary]:
        results = await extension_service.list()
        return [
            AdminExtensionSummary(
                id=ext.id,
                extension_number=ext.extension_number,
                display_name=ext.display_name,
                is_active=ext.is_active,
                owner_email=ext.user.email if ext.user else None,
                phone_number=ext.phone_number.number if ext.phone_number else None,
                created_at=ext.created_at,
            )
            for ext in results
        ]

    @get(operation_id="AdminGetVoiceStats", path="/stats")
    async def get_stats(
        self,
        phone_number_service: PhoneNumberService,
        extension_service: ExtensionService,
        dnd_service: DoNotDisturbService,
    ) -> AdminVoiceStats:
        total_phone_numbers = await phone_number_service.count()
        active_phone_numbers = await phone_number_service.count(m.PhoneNumber.is_active.is_(True))
        total_extensions = await extension_service.count()
        active_extensions = await extension_service.count(m.Extension.is_active.is_(True))
        active_dnd = await dnd_service.count(m.DoNotDisturb.is_enabled.is_(True))

        all_numbers = await phone_number_service.list()
        type_counts: dict[str, int] = {}
        for pn in all_numbers:
            type_counts[pn.number_type] = type_counts.get(pn.number_type, 0) + 1

        return AdminVoiceStats(
            total_phone_numbers=total_phone_numbers,
            active_phone_numbers=active_phone_numbers,
            total_extensions=total_extensions,
            active_extensions=active_extensions,
            active_dnd=active_dnd,
            by_number_type=type_counts,
        )
