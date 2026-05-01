"""Call Queue Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post, put
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.call_routing.deps import provide_call_queue_members_service
from app.domain.call_routing.guards import requires_call_routing_access
from app.domain.call_routing.schemas import (
    CallQueue,
    CallQueueCreate,
    CallQueueMember,
    CallQueueMemberCreate,
    CallQueueMemberPause,
    CallQueueMemberUpdate,
    CallQueueUpdate,
)
from app.domain.call_routing.services import CallQueueMemberService, CallQueueService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class CallQueueController(Controller):
    """Call Queues."""

    tags = ["Call Routing - Call Queues"]
    guards = [requires_call_routing_access]
    dependencies = create_service_dependencies(
        CallQueueService,
        key="call_queues_service",
        load=[selectinload(m.CallQueue.members)],
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
        "call_queue_members_service": Provide(provide_call_queue_members_service),
    }

    @get(operation_id="ListCallQueues", path="/api/call-queues")
    async def list_call_queues(
        self,
        call_queues_service: CallQueueService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[CallQueue]:
        """List call queues.

        Args:
            call_queues_service: Call Queue Service
            current_user: Current User
            filters: Filters

        Returns:
            OffsetPagination[CallQueue]
        """
        results, total = await call_queues_service.list_and_count(*filters)
        return call_queues_service.to_schema(results, total, filters, schema_type=CallQueue)

    @post(operation_id="CreateCallQueue", path="/api/call-queues")
    async def create_call_queue(
        self,
        request: Request[m.User, Token, Any],
        call_queues_service: CallQueueService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: CallQueueCreate,
    ) -> CallQueue:
        """Create a new call queue.

        Args:
            request: The current request
            call_queues_service: Call Queue Service
            audit_service: Audit Log Service
            current_user: Current User
            data: Call Queue Create

        Returns:
            CallQueue
        """
        obj = data.to_dict()
        obj["team_id"] = current_user.team_id if hasattr(current_user, "team_id") else None
        db_obj = await call_queues_service.create(obj)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="call_routing.call_queue.create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="call_queue",
            target_id=db_obj.id,
            target_label=db_obj.name,
            before=None,
            after=after,
            request=request,
        )
        return call_queues_service.to_schema(db_obj, schema_type=CallQueue)

    @get(operation_id="GetCallQueue", path="/api/call-queues/{call_queue_id:uuid}")
    async def get_call_queue(
        self,
        call_queues_service: CallQueueService,
        call_queue_id: Annotated[UUID, Parameter(title="Call Queue ID", description="The call queue to retrieve.")],
    ) -> CallQueue:
        """Get details about a call queue.

        Args:
            call_queues_service: Call Queue Service
            call_queue_id: Call Queue ID

        Returns:
            CallQueue
        """
        db_obj = await call_queues_service.get(call_queue_id)
        return call_queues_service.to_schema(db_obj, schema_type=CallQueue)

    @patch(operation_id="UpdateCallQueue", path="/api/call-queues/{call_queue_id:uuid}")
    async def update_call_queue(
        self,
        request: Request[m.User, Token, Any],
        data: CallQueueUpdate,
        call_queues_service: CallQueueService,
        audit_service: AuditLogService,
        current_user: m.User,
        call_queue_id: Annotated[UUID, Parameter(title="Call Queue ID", description="The call queue to update.")],
    ) -> CallQueue:
        """Update a call queue.

        Args:
            request: The current request
            data: Call Queue Update
            call_queues_service: Call Queue Service
            audit_service: Audit Log Service
            current_user: Current User
            call_queue_id: Call Queue ID

        Returns:
            CallQueue
        """
        before = capture_snapshot(await call_queues_service.get(call_queue_id))
        await call_queues_service.update(item_id=call_queue_id, data=data.to_dict())
        fresh_obj = await call_queues_service.get_one(id=call_queue_id)
        after = capture_snapshot(fresh_obj)
        await log_audit(
            audit_service,
            action="call_routing.call_queue.update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="call_queue",
            target_id=call_queue_id,
            target_label=fresh_obj.name,
            before=before,
            after=after,
            request=request,
        )
        return call_queues_service.to_schema(fresh_obj, schema_type=CallQueue)

    @delete(operation_id="DeleteCallQueue", path="/api/call-queues/{call_queue_id:uuid}", return_dto=None)
    async def delete_call_queue(
        self,
        request: Request[m.User, Token, Any],
        call_queues_service: CallQueueService,
        audit_service: AuditLogService,
        current_user: m.User,
        call_queue_id: Annotated[UUID, Parameter(title="Call Queue ID", description="The call queue to delete.")],
    ) -> None:
        """Delete a call queue.

        Args:
            request: The current request
            call_queues_service: Call Queue Service
            audit_service: Audit Log Service
            current_user: Current User
            call_queue_id: Call Queue ID
        """
        db_obj = await call_queues_service.get(call_queue_id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.name
        await call_queues_service.delete(call_queue_id)
        await log_audit(
            audit_service,
            action="call_routing.call_queue.delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="call_queue",
            target_id=call_queue_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )

    # --- Call Queue Members ---

    @get(operation_id="ListCallQueueMembers", path="/api/call-queues/{call_queue_id:uuid}/members")
    async def list_members(
        self,
        call_queues_service: CallQueueService,
        call_queue_members_service: CallQueueMemberService,
        call_queue_id: Annotated[UUID, Parameter(title="Call Queue ID", description="The call queue.")],
    ) -> list[CallQueueMember]:
        """List members of a call queue.

        Args:
            call_queues_service: Call Queue Service
            call_queue_members_service: Call Queue Member Service
            call_queue_id: Call Queue ID

        Returns:
            list[CallQueueMember]
        """
        await call_queues_service.get(call_queue_id)
        results = await call_queue_members_service.list(m.CallQueueMember.call_queue_id == call_queue_id)
        return call_queue_members_service.to_schema(results, schema_type=CallQueueMember)

    @post(operation_id="CreateCallQueueMember", path="/api/call-queues/{call_queue_id:uuid}/members")
    async def create_member(
        self,
        request: Request[m.User, Token, Any],
        call_queues_service: CallQueueService,
        call_queue_members_service: CallQueueMemberService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: CallQueueMemberCreate,
        call_queue_id: Annotated[UUID, Parameter(title="Call Queue ID", description="The call queue.")],
    ) -> CallQueueMember:
        """Add a member to a call queue.

        Args:
            request: The current request
            call_queues_service: Call Queue Service
            call_queue_members_service: Call Queue Member Service
            audit_service: Audit Log Service
            current_user: Current User
            data: Call Queue Member Create
            call_queue_id: Call Queue ID

        Returns:
            CallQueueMember
        """
        queue = await call_queues_service.get(call_queue_id)
        obj = data.to_dict()
        obj["call_queue_id"] = call_queue_id
        db_obj = await call_queue_members_service.create(obj)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="call_routing.call_queue_member.create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="call_queue_member",
            target_id=db_obj.id,
            target_label=queue.name,
            before=None,
            after=after,
            request=request,
        )
        return call_queue_members_service.to_schema(db_obj, schema_type=CallQueueMember)

    @patch(
        operation_id="UpdateCallQueueMember",
        path="/api/call-queues/{call_queue_id:uuid}/members/{member_id:uuid}",
    )
    async def update_member(
        self,
        request: Request[m.User, Token, Any],
        call_queues_service: CallQueueService,
        call_queue_members_service: CallQueueMemberService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: CallQueueMemberUpdate,
        call_queue_id: Annotated[UUID, Parameter(title="Call Queue ID", description="The call queue.")],
        member_id: Annotated[UUID, Parameter(title="Member ID", description="The member to update.")],
    ) -> CallQueueMember:
        """Update a call queue member.

        Args:
            request: The current request
            call_queues_service: Call Queue Service
            call_queue_members_service: Call Queue Member Service
            audit_service: Audit Log Service
            current_user: Current User
            data: Call Queue Member Update
            call_queue_id: Call Queue ID
            member_id: Member ID

        Returns:
            CallQueueMember
        """
        await call_queues_service.get(call_queue_id)
        before = capture_snapshot(
            await call_queue_members_service.get_one(id=member_id, call_queue_id=call_queue_id)
        )
        await call_queue_members_service.update(item_id=member_id, data=data.to_dict())
        fresh_obj = await call_queue_members_service.get_one(id=member_id)
        after = capture_snapshot(fresh_obj)
        await log_audit(
            audit_service,
            action="call_routing.call_queue_member.update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="call_queue_member",
            target_id=member_id,
            target_label=str(member_id),
            before=before,
            after=after,
            request=request,
        )
        return call_queue_members_service.to_schema(fresh_obj, schema_type=CallQueueMember)

    @delete(
        operation_id="DeleteCallQueueMember",
        path="/api/call-queues/{call_queue_id:uuid}/members/{member_id:uuid}",
        return_dto=None,
    )
    async def delete_member(
        self,
        request: Request[m.User, Token, Any],
        call_queues_service: CallQueueService,
        call_queue_members_service: CallQueueMemberService,
        audit_service: AuditLogService,
        current_user: m.User,
        call_queue_id: Annotated[UUID, Parameter(title="Call Queue ID", description="The call queue.")],
        member_id: Annotated[UUID, Parameter(title="Member ID", description="The member to remove.")],
    ) -> None:
        """Remove a member from a call queue.

        Args:
            request: The current request
            call_queues_service: Call Queue Service
            call_queue_members_service: Call Queue Member Service
            audit_service: Audit Log Service
            current_user: Current User
            call_queue_id: Call Queue ID
            member_id: Member ID
        """
        await call_queues_service.get(call_queue_id)
        db_obj = await call_queue_members_service.get_one(id=member_id, call_queue_id=call_queue_id)
        before = capture_snapshot(db_obj)
        await call_queue_members_service.delete(member_id)
        await log_audit(
            audit_service,
            action="call_routing.call_queue_member.delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="call_queue_member",
            target_id=member_id,
            target_label=str(member_id),
            before=before,
            after=None,
            request=request,
        )

    @put(
        operation_id="PauseCallQueueMember",
        path="/api/call-queues/{call_queue_id:uuid}/members/{member_id:uuid}/pause",
    )
    async def pause_member(
        self,
        request: Request[m.User, Token, Any],
        call_queues_service: CallQueueService,
        call_queue_members_service: CallQueueMemberService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: CallQueueMemberPause,
        call_queue_id: Annotated[UUID, Parameter(title="Call Queue ID", description="The call queue.")],
        member_id: Annotated[UUID, Parameter(title="Member ID", description="The member to pause/unpause.")],
    ) -> CallQueueMember:
        """Pause or unpause a call queue member.

        Args:
            request: The current request
            call_queues_service: Call Queue Service
            call_queue_members_service: Call Queue Member Service
            audit_service: Audit Log Service
            current_user: Current User
            data: Pause data
            call_queue_id: Call Queue ID
            member_id: Member ID

        Returns:
            CallQueueMember
        """
        await call_queues_service.get(call_queue_id)
        before = capture_snapshot(
            await call_queue_members_service.get_one(id=member_id, call_queue_id=call_queue_id)
        )
        await call_queue_members_service.update(
            item_id=member_id,
            data={"is_paused": data.is_paused},
        )
        fresh_obj = await call_queue_members_service.get_one(id=member_id)
        after = capture_snapshot(fresh_obj)
        await log_audit(
            audit_service,
            action="call_routing.call_queue_member.pause",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="call_queue_member",
            target_id=member_id,
            target_label=str(member_id),
            before=before,
            after=after,
            request=request,
            metadata={"is_paused": data.is_paused},
        )
        return call_queue_members_service.to_schema(fresh_obj, schema_type=CallQueueMember)
