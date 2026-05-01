"""Ring Group Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.call_routing.deps import provide_ring_group_members_service
from app.domain.call_routing.guards import requires_call_routing_access
from app.domain.call_routing.schemas import (
    RingGroup,
    RingGroupCreate,
    RingGroupMember,
    RingGroupMemberCreate,
    RingGroupMemberUpdate,
    RingGroupUpdate,
)
from app.domain.call_routing.services import RingGroupMemberService, RingGroupService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class RingGroupController(Controller):
    """Ring Groups."""

    tags = ["Call Routing - Ring Groups"]
    guards = [requires_call_routing_access]
    dependencies = create_service_dependencies(
        RingGroupService,
        key="ring_groups_service",
        load=[selectinload(m.RingGroup.members)],
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
        "ring_group_members_service": Provide(provide_ring_group_members_service),
    }

    @get(operation_id="ListRingGroups", path="/api/ring-groups")
    async def list_ring_groups(
        self,
        ring_groups_service: RingGroupService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[RingGroup]:
        """List ring groups.

        Args:
            ring_groups_service: Ring Group Service
            current_user: Current User
            filters: Filters

        Returns:
            OffsetPagination[RingGroup]
        """
        results, total = await ring_groups_service.list_and_count(*filters)
        return ring_groups_service.to_schema(results, total, filters, schema_type=RingGroup)

    @post(operation_id="CreateRingGroup", path="/api/ring-groups")
    async def create_ring_group(
        self,
        request: Request[m.User, Token, Any],
        ring_groups_service: RingGroupService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: RingGroupCreate,
    ) -> RingGroup:
        """Create a new ring group.

        Args:
            request: The current request
            ring_groups_service: Ring Group Service
            audit_service: Audit Log Service
            current_user: Current User
            data: Ring Group Create

        Returns:
            RingGroup
        """
        obj = data.to_dict()
        obj["team_id"] = current_user.team_id if hasattr(current_user, "team_id") else None
        db_obj = await ring_groups_service.create(obj)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="call_routing.ring_group.create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ring_group",
            target_id=db_obj.id,
            target_label=db_obj.name,
            before=None,
            after=after,
            request=request,
        )
        return ring_groups_service.to_schema(db_obj, schema_type=RingGroup)

    @get(operation_id="GetRingGroup", path="/api/ring-groups/{ring_group_id:uuid}")
    async def get_ring_group(
        self,
        ring_groups_service: RingGroupService,
        ring_group_id: Annotated[UUID, Parameter(title="Ring Group ID", description="The ring group to retrieve.")],
    ) -> RingGroup:
        """Get details about a ring group.

        Args:
            ring_groups_service: Ring Group Service
            ring_group_id: Ring Group ID

        Returns:
            RingGroup
        """
        db_obj = await ring_groups_service.get(ring_group_id)
        return ring_groups_service.to_schema(db_obj, schema_type=RingGroup)

    @patch(operation_id="UpdateRingGroup", path="/api/ring-groups/{ring_group_id:uuid}")
    async def update_ring_group(
        self,
        request: Request[m.User, Token, Any],
        data: RingGroupUpdate,
        ring_groups_service: RingGroupService,
        audit_service: AuditLogService,
        current_user: m.User,
        ring_group_id: Annotated[UUID, Parameter(title="Ring Group ID", description="The ring group to update.")],
    ) -> RingGroup:
        """Update a ring group.

        Args:
            request: The current request
            data: Ring Group Update
            ring_groups_service: Ring Group Service
            audit_service: Audit Log Service
            current_user: Current User
            ring_group_id: Ring Group ID

        Returns:
            RingGroup
        """
        before = capture_snapshot(await ring_groups_service.get(ring_group_id))
        await ring_groups_service.update(item_id=ring_group_id, data=data.to_dict())
        fresh_obj = await ring_groups_service.get_one(id=ring_group_id)
        after = capture_snapshot(fresh_obj)
        await log_audit(
            audit_service,
            action="call_routing.ring_group.update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ring_group",
            target_id=ring_group_id,
            target_label=fresh_obj.name,
            before=before,
            after=after,
            request=request,
        )
        return ring_groups_service.to_schema(fresh_obj, schema_type=RingGroup)

    @delete(operation_id="DeleteRingGroup", path="/api/ring-groups/{ring_group_id:uuid}", return_dto=None)
    async def delete_ring_group(
        self,
        request: Request[m.User, Token, Any],
        ring_groups_service: RingGroupService,
        audit_service: AuditLogService,
        current_user: m.User,
        ring_group_id: Annotated[UUID, Parameter(title="Ring Group ID", description="The ring group to delete.")],
    ) -> None:
        """Delete a ring group.

        Args:
            request: The current request
            ring_groups_service: Ring Group Service
            audit_service: Audit Log Service
            current_user: Current User
            ring_group_id: Ring Group ID
        """
        db_obj = await ring_groups_service.get(ring_group_id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.name
        await ring_groups_service.delete(ring_group_id)
        await log_audit(
            audit_service,
            action="call_routing.ring_group.delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ring_group",
            target_id=ring_group_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )

    # --- Ring Group Members ---

    @get(operation_id="ListRingGroupMembers", path="/api/ring-groups/{ring_group_id:uuid}/members")
    async def list_members(
        self,
        ring_groups_service: RingGroupService,
        ring_group_members_service: RingGroupMemberService,
        ring_group_id: Annotated[UUID, Parameter(title="Ring Group ID", description="The ring group.")],
    ) -> list[RingGroupMember]:
        """List members of a ring group.

        Args:
            ring_groups_service: Ring Group Service
            ring_group_members_service: Ring Group Member Service
            ring_group_id: Ring Group ID

        Returns:
            list[RingGroupMember]
        """
        await ring_groups_service.get(ring_group_id)
        results = await ring_group_members_service.list(m.RingGroupMember.ring_group_id == ring_group_id)
        return ring_group_members_service.to_schema(results, schema_type=RingGroupMember)

    @post(operation_id="CreateRingGroupMember", path="/api/ring-groups/{ring_group_id:uuid}/members")
    async def create_member(
        self,
        request: Request[m.User, Token, Any],
        ring_groups_service: RingGroupService,
        ring_group_members_service: RingGroupMemberService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: RingGroupMemberCreate,
        ring_group_id: Annotated[UUID, Parameter(title="Ring Group ID", description="The ring group.")],
    ) -> RingGroupMember:
        """Add a member to a ring group.

        Args:
            request: The current request
            ring_groups_service: Ring Group Service
            ring_group_members_service: Ring Group Member Service
            audit_service: Audit Log Service
            current_user: Current User
            data: Ring Group Member Create
            ring_group_id: Ring Group ID

        Returns:
            RingGroupMember
        """
        group = await ring_groups_service.get(ring_group_id)
        obj = data.to_dict()
        obj["ring_group_id"] = ring_group_id
        db_obj = await ring_group_members_service.create(obj)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="call_routing.ring_group_member.create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ring_group_member",
            target_id=db_obj.id,
            target_label=group.name,
            before=None,
            after=after,
            request=request,
        )
        return ring_group_members_service.to_schema(db_obj, schema_type=RingGroupMember)

    @patch(
        operation_id="UpdateRingGroupMember",
        path="/api/ring-groups/{ring_group_id:uuid}/members/{member_id:uuid}",
    )
    async def update_member(
        self,
        request: Request[m.User, Token, Any],
        ring_groups_service: RingGroupService,
        ring_group_members_service: RingGroupMemberService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: RingGroupMemberUpdate,
        ring_group_id: Annotated[UUID, Parameter(title="Ring Group ID", description="The ring group.")],
        member_id: Annotated[UUID, Parameter(title="Member ID", description="The member to update.")],
    ) -> RingGroupMember:
        """Update a ring group member.

        Args:
            request: The current request
            ring_groups_service: Ring Group Service
            ring_group_members_service: Ring Group Member Service
            audit_service: Audit Log Service
            current_user: Current User
            data: Ring Group Member Update
            ring_group_id: Ring Group ID
            member_id: Member ID

        Returns:
            RingGroupMember
        """
        await ring_groups_service.get(ring_group_id)
        before = capture_snapshot(
            await ring_group_members_service.get_one(id=member_id, ring_group_id=ring_group_id)
        )
        await ring_group_members_service.update(item_id=member_id, data=data.to_dict())
        fresh_obj = await ring_group_members_service.get_one(id=member_id)
        after = capture_snapshot(fresh_obj)
        await log_audit(
            audit_service,
            action="call_routing.ring_group_member.update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ring_group_member",
            target_id=member_id,
            target_label=str(member_id),
            before=before,
            after=after,
            request=request,
        )
        return ring_group_members_service.to_schema(fresh_obj, schema_type=RingGroupMember)

    @delete(
        operation_id="DeleteRingGroupMember",
        path="/api/ring-groups/{ring_group_id:uuid}/members/{member_id:uuid}",
        return_dto=None,
    )
    async def delete_member(
        self,
        request: Request[m.User, Token, Any],
        ring_groups_service: RingGroupService,
        ring_group_members_service: RingGroupMemberService,
        audit_service: AuditLogService,
        current_user: m.User,
        ring_group_id: Annotated[UUID, Parameter(title="Ring Group ID", description="The ring group.")],
        member_id: Annotated[UUID, Parameter(title="Member ID", description="The member to remove.")],
    ) -> None:
        """Remove a member from a ring group.

        Args:
            request: The current request
            ring_groups_service: Ring Group Service
            ring_group_members_service: Ring Group Member Service
            audit_service: Audit Log Service
            current_user: Current User
            ring_group_id: Ring Group ID
            member_id: Member ID
        """
        await ring_groups_service.get(ring_group_id)
        db_obj = await ring_group_members_service.get_one(id=member_id, ring_group_id=ring_group_id)
        before = capture_snapshot(db_obj)
        await ring_group_members_service.delete(member_id)
        await log_audit(
            audit_service,
            action="call_routing.ring_group_member.delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ring_group_member",
            target_id=member_id,
            target_label=str(member_id),
            before=before,
            after=None,
            request=request,
        )
