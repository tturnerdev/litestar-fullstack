"""Admin Music on Hold Controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from advanced_alchemy.service.pagination import OffsetPagination
from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Dependency, Parameter

from app.domain.accounts.guards import requires_superuser
from app.domain.admin.deps import provide_audit_log_service
from app.domain.admin.schemas import (
    MusicOnHoldCreate,
    MusicOnHoldDetail,
    MusicOnHoldList,
    MusicOnHoldUpdate,
)
from app.domain.admin.services import MusicOnHoldService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes, LimitOffset
    from litestar import Request
    from litestar.security.jwt import Token

    from app.db import models as m
    from app.domain.admin.services import AuditLogService


class AdminMusicOnHoldController(Controller):
    """Admin Music on Hold management endpoints."""

    tags = ["Admin"]
    path = "/api/admin/music-on-hold"
    guards = [requires_superuser]
    dependencies = create_service_dependencies(
        MusicOnHoldService,
        key="moh_service",
        filters={
            "id_filter": UUID,
            "search": "name,description",
            "pagination_type": "limit_offset",
            "pagination_size": 25,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    ) | {
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(operation_id="AdminListMusicOnHold", path="/")
    async def list_music_on_hold(
        self,
        moh_service: MusicOnHoldService,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[MusicOnHoldList]:
        """List all Music on Hold classes with search and pagination."""
        results, total = await moh_service.list_and_count(*filters)
        limit_offset = next((f for f in filters if hasattr(f, "limit")), None)
        items = [
            MusicOnHoldList(
                id=moh.id,
                name=moh.name,
                category=moh.category,
                is_default=moh.is_default,
                is_active=moh.is_active,
                file_count=len(moh.file_list) if moh.file_list else 0,
                created_at=moh.created_at,
            )
            for moh in results
        ]
        return OffsetPagination(
            items=items,
            total=total,
            limit=limit_offset.limit if limit_offset else 25,
            offset=limit_offset.offset if limit_offset else 0,
        )

    @post(operation_id="AdminCreateMusicOnHold", path="/")
    async def create_music_on_hold(
        self,
        request: Request[m.User, Token, Any],
        moh_service: MusicOnHoldService,
        audit_service: AuditLogService,
        data: MusicOnHoldCreate,
    ) -> MusicOnHoldDetail:
        """Create a new Music on Hold class."""
        db_obj = await moh_service.create(data.to_dict())
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="admin.music_on_hold_create",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="music_on_hold",
            target_id=db_obj.id,
            target_label=db_obj.name,
            before=None,
            after=after,
            request=request,
        )
        return MusicOnHoldDetail(
            id=db_obj.id,
            name=db_obj.name,
            description=db_obj.description,
            category=db_obj.category,
            is_default=db_obj.is_default,
            is_active=db_obj.is_active,
            random_order=db_obj.random_order,
            file_list=db_obj.file_list or [],
            created_at=db_obj.created_at,
            updated_at=db_obj.updated_at,
        )

    @get(operation_id="AdminGetMusicOnHold", path="/{moh_id:uuid}")
    async def get_music_on_hold(
        self,
        moh_service: MusicOnHoldService,
        moh_id: Annotated[UUID, Parameter(title="MOH ID", description="The Music on Hold class to retrieve.")],
    ) -> MusicOnHoldDetail:
        """Get a Music on Hold class by ID."""
        db_obj = await moh_service.get(moh_id)
        return MusicOnHoldDetail(
            id=db_obj.id,
            name=db_obj.name,
            description=db_obj.description,
            category=db_obj.category,
            is_default=db_obj.is_default,
            is_active=db_obj.is_active,
            random_order=db_obj.random_order,
            file_list=db_obj.file_list or [],
            created_at=db_obj.created_at,
            updated_at=db_obj.updated_at,
        )

    @patch(operation_id="AdminUpdateMusicOnHold", path="/{moh_id:uuid}")
    async def update_music_on_hold(
        self,
        request: Request[m.User, Token, Any],
        moh_service: MusicOnHoldService,
        audit_service: AuditLogService,
        data: MusicOnHoldUpdate,
        moh_id: Annotated[UUID, Parameter(title="MOH ID", description="The Music on Hold class to update.")],
    ) -> MusicOnHoldDetail:
        """Update a Music on Hold class."""
        db_obj = await moh_service.get(moh_id)
        before = capture_snapshot(db_obj)
        db_obj = await moh_service.update(
            item_id=moh_id,
            data=data.to_dict(),
        )
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="admin.music_on_hold_update",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="music_on_hold",
            target_id=db_obj.id,
            target_label=db_obj.name,
            before=before,
            after=after,
            request=request,
        )
        return MusicOnHoldDetail(
            id=db_obj.id,
            name=db_obj.name,
            description=db_obj.description,
            category=db_obj.category,
            is_default=db_obj.is_default,
            is_active=db_obj.is_active,
            random_order=db_obj.random_order,
            file_list=db_obj.file_list or [],
            created_at=db_obj.created_at,
            updated_at=db_obj.updated_at,
        )

    @delete(operation_id="AdminDeleteMusicOnHold", path="/{moh_id:uuid}")
    async def delete_music_on_hold(
        self,
        request: Request[m.User, Token, Any],
        moh_service: MusicOnHoldService,
        audit_service: AuditLogService,
        moh_id: Annotated[UUID, Parameter(title="MOH ID", description="The Music on Hold class to delete.")],
    ) -> None:
        """Delete a Music on Hold class."""
        db_obj = await moh_service.get(moh_id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.name
        await moh_service.delete(moh_id)
        await log_audit(
            audit_service,
            action="admin.music_on_hold_delete",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="music_on_hold",
            target_id=moh_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )
