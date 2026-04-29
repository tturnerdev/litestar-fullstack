"""Extension Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Dependency, Parameter

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.notifications.deps import provide_notifications_service
from app.domain.voice.guards import requires_extension_ownership
from app.domain.voice.schemas import Extension, ExtensionCreate, ExtensionUpdate
from app.domain.voice.services import ExtensionService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService
    from app.domain.notifications.services import NotificationService


class ExtensionController(Controller):
    """Extensions."""

    tags = ["Voice - Extensions"]
    path = "/api/voice/extensions"
    dependencies = create_service_dependencies(
        ExtensionService,
        key="extensions_service",
        filters={
            "id_filter": UUID,
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "created_at",
            "sort_order": "desc",
        },
    ) | {
        "audit_service": Provide(provide_audit_log_service),
        "notifications_service": Provide(provide_notifications_service),
    }

    @get(operation_id="ListExtensions")
    async def list_extensions(
        self,
        extensions_service: ExtensionService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[Extension]:
        """List user's extensions."""
        results, total = await extensions_service.list_and_count(
            *filters,
            m.Extension.user_id == current_user.id,
        )
        return extensions_service.to_schema(results, total, filters, schema_type=Extension)

    @post(operation_id="CreateExtension")
    async def create_extension(
        self,
        request: Request[m.User, Token, Any],
        extensions_service: ExtensionService,
        audit_service: AuditLogService,
        notifications_service: NotificationService,
        current_user: m.User,
        data: ExtensionCreate,
    ) -> Extension:
        """Create a new extension."""
        obj = data.to_dict()
        obj["user_id"] = current_user.id
        db_obj = await extensions_service.create(obj)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="voice.extension_create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="extension",
            target_id=db_obj.id,
            target_label=db_obj.extension_number,
            before=None,
            after=after,
            request=request,
        )
        try:
            await notifications_service.notify(
                user_id=current_user.id,
                title="Extension Created",
                message=f"Your extension '{db_obj.extension_number}' has been created.",
                category="voice",
                action_url=f"/voice/extensions/{db_obj.id}",
            )
        except Exception:
            pass
        return extensions_service.to_schema(db_obj, schema_type=Extension)

    @get(operation_id="GetExtension", path="/{ext_id:uuid}", guards=[requires_extension_ownership])
    async def get_extension(
        self,
        extensions_service: ExtensionService,
        current_user: m.User,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension to retrieve.")],
    ) -> Extension:
        """Get extension details."""
        db_obj = await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        return extensions_service.to_schema(db_obj, schema_type=Extension)

    @patch(operation_id="UpdateExtension", path="/{ext_id:uuid}", guards=[requires_extension_ownership])
    async def update_extension(
        self,
        request: Request[m.User, Token, Any],
        extensions_service: ExtensionService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: ExtensionUpdate,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension to update.")],
    ) -> Extension:
        """Update display name, settings."""
        db_obj = await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        before = capture_snapshot(db_obj)
        db_obj = await extensions_service.update(item_id=db_obj.id, data=data.to_dict())
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="voice.extension_update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="extension",
            target_id=db_obj.id,
            target_label=db_obj.extension_number,
            before=before,
            after=after,
            request=request,
        )
        return extensions_service.to_schema(db_obj, schema_type=Extension)

    @delete(
        operation_id="DeleteExtension",
        path="/{ext_id:uuid}",
        guards=[requires_extension_ownership],
        return_dto=None,
    )
    async def delete_extension(
        self,
        request: Request[m.User, Token, Any],
        extensions_service: ExtensionService,
        audit_service: AuditLogService,
        current_user: m.User,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension to delete.")],
    ) -> None:
        """Delete an extension."""
        db_obj = await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.extension_number
        await extensions_service.delete(ext_id)
        await log_audit(
            audit_service,
            action="voice.extension_delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            target_type="extension",
            target_id=ext_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )
