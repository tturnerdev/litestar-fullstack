"""Time Condition Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post, put
from litestar.di import Provide
from litestar.params import Dependency, Parameter

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.call_routing.guards import requires_call_routing_access
from app.domain.call_routing.schemas import (
    TimeCondition,
    TimeConditionCreate,
    TimeConditionOverride,
    TimeConditionUpdate,
)
from app.domain.call_routing.services import TimeConditionService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class TimeConditionController(Controller):
    """Time Conditions."""

    tags = ["Call Routing - Time Conditions"]
    guards = [requires_call_routing_access]
    dependencies = create_service_dependencies(
        TimeConditionService,
        key="time_conditions_service",
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

    @get(operation_id="ListTimeConditions", path="/api/time-conditions")
    async def list_time_conditions(
        self,
        time_conditions_service: TimeConditionService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[TimeCondition]:
        """List time conditions.

        Args:
            time_conditions_service: Time Condition Service
            current_user: Current User
            filters: Filters

        Returns:
            OffsetPagination[TimeCondition]
        """
        results, total = await time_conditions_service.list_and_count(*filters)
        return time_conditions_service.to_schema(results, total, filters, schema_type=TimeCondition)

    @post(operation_id="CreateTimeCondition", path="/api/time-conditions")
    async def create_time_condition(
        self,
        request: Request[m.User, Token, Any],
        time_conditions_service: TimeConditionService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: TimeConditionCreate,
    ) -> TimeCondition:
        """Create a new time condition.

        Args:
            request: The current request
            time_conditions_service: Time Condition Service
            audit_service: Audit Log Service
            current_user: Current User
            data: Time Condition Create

        Returns:
            TimeCondition
        """
        obj = data.to_dict()
        obj["team_id"] = current_user.team_id if hasattr(current_user, "team_id") else None
        db_obj = await time_conditions_service.create(obj)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="call_routing.time_condition.create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="time_condition",
            target_id=db_obj.id,
            target_label=db_obj.name,
            before=None,
            after=after,
            request=request,
        )
        return time_conditions_service.to_schema(db_obj, schema_type=TimeCondition)

    @get(operation_id="GetTimeCondition", path="/api/time-conditions/{time_condition_id:uuid}")
    async def get_time_condition(
        self,
        time_conditions_service: TimeConditionService,
        time_condition_id: Annotated[
            UUID, Parameter(title="Time Condition ID", description="The time condition to retrieve.")
        ],
    ) -> TimeCondition:
        """Get details about a time condition.

        Args:
            time_conditions_service: Time Condition Service
            time_condition_id: Time Condition ID

        Returns:
            TimeCondition
        """
        db_obj = await time_conditions_service.get(time_condition_id)
        return time_conditions_service.to_schema(db_obj, schema_type=TimeCondition)

    @patch(operation_id="UpdateTimeCondition", path="/api/time-conditions/{time_condition_id:uuid}")
    async def update_time_condition(
        self,
        request: Request[m.User, Token, Any],
        data: TimeConditionUpdate,
        time_conditions_service: TimeConditionService,
        audit_service: AuditLogService,
        current_user: m.User,
        time_condition_id: Annotated[
            UUID, Parameter(title="Time Condition ID", description="The time condition to update.")
        ],
    ) -> TimeCondition:
        """Update a time condition.

        Args:
            request: The current request
            data: Time Condition Update
            time_conditions_service: Time Condition Service
            audit_service: Audit Log Service
            current_user: Current User
            time_condition_id: Time Condition ID

        Returns:
            TimeCondition
        """
        before = capture_snapshot(await time_conditions_service.get(time_condition_id))
        await time_conditions_service.update(item_id=time_condition_id, data=data.to_dict())
        fresh_obj = await time_conditions_service.get_one(id=time_condition_id)
        after = capture_snapshot(fresh_obj)
        await log_audit(
            audit_service,
            action="call_routing.time_condition.update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="time_condition",
            target_id=time_condition_id,
            target_label=fresh_obj.name,
            before=before,
            after=after,
            request=request,
        )
        return time_conditions_service.to_schema(fresh_obj, schema_type=TimeCondition)

    @delete(operation_id="DeleteTimeCondition", path="/api/time-conditions/{time_condition_id:uuid}", return_dto=None)
    async def delete_time_condition(
        self,
        request: Request[m.User, Token, Any],
        time_conditions_service: TimeConditionService,
        audit_service: AuditLogService,
        current_user: m.User,
        time_condition_id: Annotated[
            UUID, Parameter(title="Time Condition ID", description="The time condition to delete.")
        ],
    ) -> None:
        """Delete a time condition.

        Args:
            request: The current request
            time_conditions_service: Time Condition Service
            audit_service: Audit Log Service
            current_user: Current User
            time_condition_id: Time Condition ID
        """
        db_obj = await time_conditions_service.get(time_condition_id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.name
        await time_conditions_service.delete(time_condition_id)
        await log_audit(
            audit_service,
            action="call_routing.time_condition.delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="time_condition",
            target_id=time_condition_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )

    @put(
        operation_id="SetTimeConditionOverride",
        path="/api/time-conditions/{time_condition_id:uuid}/override",
    )
    async def set_override(
        self,
        request: Request[m.User, Token, Any],
        data: TimeConditionOverride,
        time_conditions_service: TimeConditionService,
        audit_service: AuditLogService,
        current_user: m.User,
        time_condition_id: Annotated[
            UUID, Parameter(title="Time Condition ID", description="The time condition to override.")
        ],
    ) -> TimeCondition:
        """Set override mode on a time condition.

        Args:
            request: The current request
            data: Override mode data
            time_conditions_service: Time Condition Service
            audit_service: Audit Log Service
            current_user: Current User
            time_condition_id: Time Condition ID

        Returns:
            TimeCondition
        """
        before = capture_snapshot(await time_conditions_service.get(time_condition_id))
        await time_conditions_service.update(
            item_id=time_condition_id,
            data={"override_mode": data.override_mode},
        )
        fresh_obj = await time_conditions_service.get_one(id=time_condition_id)
        after = capture_snapshot(fresh_obj)
        await log_audit(
            audit_service,
            action="call_routing.time_condition.override",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="time_condition",
            target_id=time_condition_id,
            target_label=fresh_obj.name,
            before=before,
            after=after,
            request=request,
        )
        return time_conditions_service.to_schema(fresh_obj, schema_type=TimeCondition)
