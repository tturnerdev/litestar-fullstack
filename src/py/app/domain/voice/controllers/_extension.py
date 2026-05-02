"""Extension Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from structlog import get_logger
from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.exceptions import ClientException
from litestar.params import Dependency, Parameter
from sqlalchemy.orm import joinedload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.gateway.deps import provide_gateway_connections
from app.domain.gateway.providers import FreePBXProvider
from app.domain.gateway.providers._freepbx import _GQL_ALL_EXTENSIONS, _GQL_EXTENSION, _to_bool, _to_int
from app.domain.tasks.deps import provide_background_tasks_service
from app.domain.teams.guards import requires_feature_permission
from app.domain.voice.guards import requires_extension_ownership
from app.domain.voice.jobs import extension_create_job, extension_delete_job, extension_update_job
from app.domain.voice.schemas import Extension, ExtensionCreate, ExtensionSyncResult, ExtensionUpdate
from app.domain.voice.services import ExtensionService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

logger = get_logger()

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService
    from app.domain.tasks.services import BackgroundTaskService


class ExtensionController(Controller):
    """Extensions."""

    tags = ["Voice - Extensions"]
    path = "/api/voice/extensions"
    dependencies = create_service_dependencies(
        ExtensionService,
        key="extensions_service",
        load=[joinedload(m.Extension.phone_number).joinedload(m.PhoneNumber.e911_registration)],
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
        "gateway_connections": Provide(provide_gateway_connections),
        "task_service": Provide(provide_background_tasks_service),
    }

    @get(
        operation_id="ListExtensions",
        guards=[requires_feature_permission("voice", "view")],
    )
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

    @post(
        operation_id="CreateExtension",
        guards=[requires_feature_permission("voice", "edit")],
    )
    async def create_extension(
        self,
        request: Request[m.User, Token, Any],
        extensions_service: ExtensionService,
        audit_service: AuditLogService,
        task_service: BackgroundTaskService,
        current_user: m.User,
        data: ExtensionCreate,
        gateway_connections: list[m.Connection],
    ) -> Extension:
        """Create a new extension."""
        # Check if extension already exists on PBX
        ext_exists_on_pbx = False
        pbx_connections = [c for c in gateway_connections if c.provider == "freepbx" and c.is_enabled]
        if pbx_connections:
            conn = pbx_connections[0]
            provider = FreePBXProvider()
            try:
                ext_query = _GQL_EXTENSION.format(ext=data.extension_number)
                resp = await provider._execute_graphql(ext_query, conn)
                ext_data = resp.get("data", {}).get("fetchExtension", {})
                ext_status = ext_data.get("status", "")
                if str(ext_status).lower() in ("true", "ok", "success", "1"):
                    ext_exists_on_pbx = True
                    user_data = ext_data.get("user") or {}
                    if user_data.get("name"):
                        raise ClientException(
                            detail=f"Extension {data.extension_number} already exists on PBX server '{conn.name}' "
                            f"(assigned to {user_data.get('name', 'unknown')}). "
                            f"Use the Sync button to import it instead.",
                            status_code=409,
                        )
            except ClientException:
                raise
            except Exception:
                pass

        obj = data.to_dict()
        obj["user_id"] = current_user.id
        db_obj = await extensions_service.create(obj)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="voice.extension.created",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="extension",
            target_id=db_obj.id,
            target_label=db_obj.extension_number,
            before=None,
            after=after,
            request=request,
        )

        # Enqueue background PBX sync task
        if not ext_exists_on_pbx:
            team_id = current_user.teams[0].team_id if current_user.teams else None
            if team_id is not None:
                await task_service.enqueue_tracked_task(
                    task_type="extension.create",
                    job_function=extension_create_job,
                    team_id=team_id,
                    initiated_by_id=request.user.id,
                    entity_type="extension",
                    entity_id=db_obj.id,
                    payload={"extension_id": str(db_obj.id), "extension_number": db_obj.extension_number},
                )

        return extensions_service.to_schema(db_obj, schema_type=Extension)

    @get(
        operation_id="GetExtension",
        path="/{ext_id:uuid}",
        guards=[requires_feature_permission("voice", "view"), requires_extension_ownership],
    )
    async def get_extension(
        self,
        extensions_service: ExtensionService,
        current_user: m.User,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension to retrieve.")],
    ) -> Extension:
        """Get extension details."""
        db_obj = await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        return extensions_service.to_schema_enriched(db_obj)

    @patch(
        operation_id="UpdateExtension",
        path="/{ext_id:uuid}",
        guards=[requires_feature_permission("voice", "edit"), requires_extension_ownership],
    )
    async def update_extension(
        self,
        request: Request[m.User, Token, Any],
        extensions_service: ExtensionService,
        audit_service: AuditLogService,
        task_service: BackgroundTaskService,
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
            action="voice.extension.updated",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="extension",
            target_id=db_obj.id,
            target_label=db_obj.extension_number,
            before=before,
            after=after,
            request=request,
        )

        # Enqueue background PBX sync task
        team_id = current_user.teams[0].team_id if current_user.teams else None
        if team_id is not None:
            await task_service.enqueue_tracked_task(
                task_type="extension.update",
                job_function=extension_update_job,
                team_id=team_id,
                initiated_by_id=request.user.id,
                entity_type="extension",
                entity_id=db_obj.id,
                payload={"extension_id": str(db_obj.id), "extension_number": db_obj.extension_number},
            )

        return extensions_service.to_schema(db_obj, schema_type=Extension)

    @delete(
        operation_id="DeleteExtension",
        path="/{ext_id:uuid}",
        guards=[requires_feature_permission("voice", "edit"), requires_extension_ownership],
        return_dto=None,
    )
    async def delete_extension(
        self,
        request: Request[m.User, Token, Any],
        extensions_service: ExtensionService,
        audit_service: AuditLogService,
        task_service: BackgroundTaskService,
        current_user: m.User,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension to delete.")],
    ) -> None:
        """Delete an extension."""
        db_obj = await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.extension_number
        extension_number = db_obj.extension_number
        await extensions_service.delete(ext_id)
        await log_audit(
            audit_service,
            action="voice.extension.deleted",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="extension",
            target_id=ext_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )

        # Enqueue background PBX sync task
        team_id = current_user.teams[0].team_id if current_user.teams else None
        if team_id is not None:
            await task_service.enqueue_tracked_task(
                task_type="extension.delete",
                job_function=extension_delete_job,
                team_id=team_id,
                initiated_by_id=request.user.id,
                entity_type="extension",
                entity_id=ext_id,
                payload={"extension_id": str(ext_id), "extension_number": extension_number},
            )

    @post(
        operation_id="SyncExtensions",
        path="/sync",
        guards=[requires_feature_permission("voice", "edit")],
    )
    async def sync_extensions(
        self,
        request: Request[m.User, Token, Any],
        extensions_service: ExtensionService,
        audit_service: AuditLogService,
        current_user: m.User,
        gateway_connections: list[m.Connection],
    ) -> ExtensionSyncResult:
        """Sync extensions from a connected PBX server.

        Fetches all extensions from the first enabled FreePBX connection,
        creates new portal extensions for unknown ones, and updates existing
        portal extensions to match PBX data.
        """
        pbx_connections = [c for c in gateway_connections if c.provider == "freepbx" and c.is_enabled]
        if not pbx_connections:
            return ExtensionSyncResult(created=0, updated=0, errors=[], connection_name=None)

        conn = pbx_connections[0]
        provider = FreePBXProvider()

        resp = await provider._execute_graphql(_GQL_ALL_EXTENSIONS, conn)
        ext_data = resp.get("data", {}).get("fetchAllExtensions", {})
        pbx_extensions: list[dict[str, Any]] = ext_data.get("extension", []) or []

        created = 0
        updated = 0
        errors: list[str] = []

        for pbx_ext in pbx_extensions:
            ext_number = pbx_ext.get("extensionId", "")
            if not ext_number:
                continue
            user = pbx_ext.get("user") or {}

            display_name = user.get("name", "") or f"Extension {ext_number}"
            dnd_enabled = _to_bool(user.get("donotdisturb"))
            no_answer_dest = user.get("noanswerDestination", "") or ""
            ring_timer = _to_int(user.get("ringtimer"))

            try:
                existing = await extensions_service.get_by_extension_number(ext_number)
                if existing:
                    update_data = {
                        "display_name": display_name,
                        "dnd_enabled": dnd_enabled,
                        "forward_no_answer_destination": no_answer_dest or None,
                        "forward_no_answer_enabled": bool(no_answer_dest),
                        "forward_no_answer_ring_count": ring_timer if ring_timer > 0 else 4,
                    }
                    await extensions_service.update(item_id=existing.id, data=update_data)
                    updated += 1
                else:
                    create_data = {
                        "extension_number": ext_number,
                        "display_name": display_name,
                        "user_id": current_user.id,
                        "is_active": True,
                        "dnd_enabled": dnd_enabled,
                        "forward_no_answer_destination": no_answer_dest or None,
                        "forward_no_answer_enabled": bool(no_answer_dest),
                        "forward_no_answer_ring_count": ring_timer if ring_timer > 0 else 4,
                    }
                    await extensions_service.create(create_data)
                    created += 1
            except Exception as exc:
                errors.append(f"Extension {ext_number}: {exc!s}")

        await log_audit(
            audit_service,
            action="voice.extensions.synced",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="extension",
            target_id=current_user.id,
            target_label=f"PBX sync: {conn.name}",
            before=None,
            after={"created": created, "updated": updated, "errors": errors},
            request=request,
        )

        return ExtensionSyncResult(
            created=created,
            updated=updated,
            errors=errors,
            connection_name=conn.name,
        )
