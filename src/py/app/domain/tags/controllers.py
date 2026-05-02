"""Tag Controllers."""

from __future__ import annotations

from datetime import date, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.accounts.guards import requires_superuser
from app.domain.admin.deps import provide_audit_log_service
from app.domain.tags.schemas import Tag, TagCreate, TagUpdate
from app.domain.tags.services import TagService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from typing import Annotated

    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService

_SNAPSHOT_EXCLUDE: frozenset[str] = frozenset(
    {"id", "sa_orm_sentinel", "created_at", "updated_at", "hashed_password", "totp_secret", "backup_codes"}
)


def _capture_snapshot(obj: Any) -> dict[str, Any]:
    """Serialize a SQLAlchemy model instance to a plain dict for audit details."""
    mapper = sa_inspect(type(obj))
    result: dict[str, Any] = {}
    for col in mapper.columns:
        key = col.key
        if key in _SNAPSHOT_EXCLUDE:
            continue
        try:
            value = getattr(obj, key)
        except Exception:  # noqa: BLE001, S112
            continue
        if isinstance(value, UUID):
            value = str(value)
        elif isinstance(value, (datetime, date)):
            value = value.isoformat()
        result[key] = value
    return result


async def _log_audit(
    audit_service: AuditLogService,
    *,
    action: str,
    actor: m.User,
    target_type: str,
    target_id: UUID,
    target_label: str,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    request: Request[Any, Any, Any] | None = None,
) -> None:
    """Write an audit log entry with optional before/after diff."""
    details: dict[str, Any] = {}
    if before is not None or after is not None:
        if before is None:
            details = {"before": None, "after": after}
        elif after is None:
            details = {"before": before, "after": None}
        else:
            changed_before: dict[str, Any] = {}
            changed_after: dict[str, Any] = {}
            for key in set(before) | set(after):
                if before.get(key) != after.get(key):
                    changed_before[key] = before.get(key)
                    changed_after[key] = after.get(key)
            if changed_before or changed_after:
                details = {"before": changed_before, "after": changed_after}

    await audit_service.log_action(
        action=action,
        actor_id=actor.id,
        actor_email=actor.email,
        actor_name=actor.name,
        target_type=target_type,
        target_id=str(target_id),
        target_label=target_label,
        details=details or None,
        request=request,
    )


class TagController(Controller):
    """Tags."""

    tags = ["Tags"]
    path = "/api/tags"
    dependencies = create_service_dependencies(
        TagService,
        key="tags_service",
        load=[selectinload(m.Tag.teams)],
        filters={
            "id_filter": UUID,
            "search": "name",
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "name",
            "sort_order": "asc",
        },
    ) | {
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(operation_id="ListTags")
    async def list_tags(
        self,
        tags_service: TagService,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[Tag]:
        """List tags.

        Args:
            filters: The filters to apply to the list of tags.
            tags_service: The tag service.

        Returns:
            The list of tags.
        """
        results, total = await tags_service.list_and_count(*filters)
        return tags_service.to_schema(results, total, filters, schema_type=Tag)

    @get(operation_id="GetTag", path="/{tag_id:uuid}")
    async def get_tag(
        self,
        tags_service: TagService,
        tag_id: Annotated[UUID, Parameter(title="Tag ID", description="The tag to retrieve.")],
    ) -> Tag:
        """Get a tag.

        Args:
            tag_id: The ID of the tag to retrieve.
            tags_service: The tag service.

        Returns:
            The tag.
        """
        db_obj = await tags_service.get(tag_id)
        return tags_service.to_schema(db_obj, schema_type=Tag)

    @post(operation_id="CreateTag", path="", guards=[requires_superuser])
    async def create_tag(
        self,
        request: Request[m.User, Token, Any],
        tags_service: TagService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: TagCreate,
    ) -> Tag:
        """Create a new tag.

        Args:
            request: The current request
            data: The data to create the tag with.
            tags_service: The tag service.
            audit_service: Audit Log Service
            current_user: Current User

        Returns:
            The created tag.
        """
        db_obj = await tags_service.create(data.to_dict())
        after = _capture_snapshot(db_obj)
        await _log_audit(
            audit_service,
            action="tag.created",
            actor=current_user,
            target_type="tag",
            target_id=db_obj.id,
            target_label=db_obj.name,
            after=after,
            request=request,
        )
        return tags_service.to_schema(db_obj, schema_type=Tag)

    @patch(operation_id="UpdateTag", path="/{tag_id:uuid}", guards=[requires_superuser])
    async def update_tag(
        self,
        request: Request[m.User, Token, Any],
        data: TagUpdate,
        tags_service: TagService,
        audit_service: AuditLogService,
        current_user: m.User,
        tag_id: Annotated[UUID, Parameter(title="Tag ID", description="The tag to update.")],
    ) -> Tag:
        """Update a tag.

        Args:
            request: The current request
            data: The data to update the tag with.
            tag_id: The ID of the tag to update.
            tags_service: The tag service.
            audit_service: Audit Log Service
            current_user: Current User

        Returns:
            The updated tag.
        """
        before = _capture_snapshot(await tags_service.get(tag_id))
        await tags_service.update(item_id=tag_id, data=data.to_dict())
        fresh_obj = await tags_service.get_one(id=tag_id)
        after = _capture_snapshot(fresh_obj)
        await _log_audit(
            audit_service,
            action="tag.updated",
            actor=current_user,
            target_type="tag",
            target_id=tag_id,
            target_label=fresh_obj.name,
            before=before,
            after=after,
            request=request,
        )
        return tags_service.to_schema(fresh_obj, schema_type=Tag)

    @delete(operation_id="DeleteTag", path="/{tag_id:uuid}", guards=[requires_superuser], return_dto=None)
    async def delete_tag(
        self,
        request: Request[m.User, Token, Any],
        tags_service: TagService,
        audit_service: AuditLogService,
        current_user: m.User,
        tag_id: Annotated[UUID, Parameter(title="Tag ID", description="The tag to delete.")],
    ) -> None:
        """Delete a tag.

        Args:
            request: The current request
            tag_id: The ID of the tag to delete.
            tags_service: The tag service.
            audit_service: Audit Log Service
            current_user: Current User
        """
        db_obj = await tags_service.get(tag_id)
        before = _capture_snapshot(db_obj)
        target_label = db_obj.name
        await tags_service.delete(tag_id)
        await _log_audit(
            audit_service,
            action="tag.deleted",
            actor=current_user,
            target_type="tag",
            target_id=tag_id,
            target_label=target_label,
            before=before,
            request=request,
        )
