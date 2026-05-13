"""Location Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.exceptions import ClientException
from litestar.params import Dependency, Parameter
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.locations.guards import requires_location_team_membership
from app.domain.locations.schemas import Location, LocationCreate, LocationUpdate
from app.domain.locations.services import LocationService
from app.domain.teams.guards import requires_feature_permission
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class LocationController(Controller):
    """Locations."""

    tags = ["Locations"]
    dependencies = create_service_dependencies(
        LocationService,
        key="locations_service",
        load=[selectinload(m.Location.children)],
        filters={
            "id_filter": UUID,
            "search": "name,city,state",
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

    @get(
        operation_id="ListLocations",
        summary="List locations",
        description="Retrieve a paginated list of locations for a team. Supports searching by name, city, and state, and optional filtering by location type.",
        path="/api/teams/{team_id:uuid}/locations",
        guards=[requires_feature_permission("locations", "view")],
    )
    async def list_locations(
        self,
        locations_service: LocationService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team to list locations for.")],
        location_type: Annotated[
            str | None,
            Parameter(
                title="Location Type", description="Filter by location type.", query="locationType", required=False
            ),
        ] = None,
    ) -> OffsetPagination[Location]:
        """List locations for a team.

        Args:
            locations_service: Location Service
            current_user: Current User
            filters: Filters
            team_id: Team ID
            location_type: Optional location type filter

        Returns:
            OffsetPagination[Location]
        """
        extra_filters = [m.Location.team_id == team_id]
        if location_type:
            extra_filters.append(m.Location.location_type == location_type)
        results, total = await locations_service.list_and_count(*filters, *extra_filters)
        return await locations_service.to_schema_enriched(results, total, filters)

    @post(
        operation_id="CreateLocation",
        summary="Create a location",
        description="Create a new location within a team. Requires team membership. Records an audit log entry and emits a location_created event.",
        path="/api/teams/{team_id:uuid}/locations",
        guards=[requires_feature_permission("locations", "edit"), requires_location_team_membership],
        status_code=HTTP_201_CREATED,
    )
    async def create_location(
        self,
        request: Request[m.User, Token, Any],
        locations_service: LocationService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: LocationCreate,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team to create the location for.")],
    ) -> Location:
        """Create a new location.

        Args:
            request: The current request
            locations_service: Location Service
            audit_service: Audit Log Service
            current_user: Current User
            data: Location Create
            team_id: Team ID

        Returns:
            Location
        """
        obj = data.to_dict()
        obj["team_id"] = team_id
        db_obj = await locations_service.create(obj)
        result = await locations_service.to_schema_enriched(db_obj)
        request.app.emit(event_id="location_created", location_id=db_obj.id)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="location.created",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="location",
            target_id=db_obj.id,
            target_label=db_obj.name,
            before=None,
            after=after,
            request=request,
        )
        return result

    @get(
        operation_id="GetLocation",
        summary="Get location details",
        description="Retrieve details for a single location, including its child locations. Scoped to the specified team.",
        path="/api/teams/{team_id:uuid}/locations/{location_id:uuid}",
        guards=[requires_feature_permission("locations", "view"), requires_location_team_membership],
    )
    async def get_location(
        self,
        locations_service: LocationService,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team the location belongs to.")],
        location_id: Annotated[UUID, Parameter(title="Location ID", description="The location to retrieve.")],
    ) -> Location:
        """Get details about a location.

        Args:
            locations_service: Location Service
            team_id: Team ID
            location_id: Location ID

        Returns:
            Location
        """
        db_obj = await locations_service.get(location_id)
        return await locations_service.to_schema_enriched(db_obj)

    @patch(
        operation_id="UpdateLocation",
        summary="Update a location",
        description="Update an existing location's attributes. Requires team membership. Records an audit log entry and emits a location_updated event.",
        path="/api/teams/{team_id:uuid}/locations/{location_id:uuid}",
        guards=[requires_feature_permission("locations", "edit"), requires_location_team_membership],
    )
    async def update_location(
        self,
        request: Request[m.User, Token, Any],
        data: LocationUpdate,
        locations_service: LocationService,
        audit_service: AuditLogService,
        current_user: m.User,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team the location belongs to.")],
        location_id: Annotated[UUID, Parameter(title="Location ID", description="The location to update.")],
    ) -> Location:
        """Update a location.

        Args:
            request: The current request
            data: Location Update
            locations_service: Location Service
            audit_service: Audit Log Service
            current_user: Current User
            team_id: Team ID
            location_id: Location ID

        Returns:
            Location
        """
        before = capture_snapshot(await locations_service.get(location_id))
        fresh_obj = await locations_service.update(
            item_id=location_id,
            data=data.to_dict(),
        )
        result = await locations_service.to_schema_enriched(fresh_obj)
        request.app.emit(event_id="location_updated", location_id=fresh_obj.id)
        after = capture_snapshot(fresh_obj)
        await log_audit(
            audit_service,
            action="location.updated",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="location",
            target_id=location_id,
            target_label=fresh_obj.name,
            before=before,
            after=after,
            request=request,
        )
        return result

    @delete(
        operation_id="DeleteLocation",
        summary="Delete a location",
        description="Delete a location from a team. Fails with HTTP 409 if devices are still assigned to the location. Records an audit log entry.",
        path="/api/teams/{team_id:uuid}/locations/{location_id:uuid}",
        guards=[requires_feature_permission("locations", "edit"), requires_location_team_membership],
        status_code=HTTP_204_NO_CONTENT,
        return_dto=None,
    )
    async def delete_location(
        self,
        request: Request[m.User, Token, Any],
        locations_service: LocationService,
        audit_service: AuditLogService,
        current_user: m.User,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team the location belongs to.")],
        location_id: Annotated[UUID, Parameter(title="Location ID", description="The location to delete.")],
    ) -> None:
        """Delete a location.

        Args:
            request: The current request
            locations_service: Location Service
            audit_service: Audit Log Service
            current_user: Current User
            team_id: Team ID
            location_id: Location ID
        """
        db_obj = await locations_service.get(location_id)
        device_count = await locations_service.get_device_count(location_id)
        if device_count > 0:
            raise ClientException(
                detail=f"Cannot delete location with {device_count} assigned device(s). Reassign devices first.",
                status_code=409,
            )
        before = capture_snapshot(db_obj)
        target_label = db_obj.name
        request.app.emit(event_id="location_deleted", location_id=location_id)
        await locations_service.delete(location_id)
        await log_audit(
            audit_service,
            action="location.deleted",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="location",
            target_id=location_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )
