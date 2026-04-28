"""Location Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.params import Dependency, Parameter
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.locations.guards import requires_location_team_membership
from app.domain.locations.schemas import Location, LocationCreate, LocationUpdate
from app.domain.locations.services import LocationService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination


class LocationController(Controller):
    """Locations."""

    tags = ["Locations"]
    dependencies = create_service_dependencies(
        LocationService,
        key="locations_service",
        load=[selectinload(m.Location.children)],
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
    )

    @get(operation_id="ListLocations", path="/api/teams/{team_id:uuid}/locations")
    async def list_locations(
        self,
        locations_service: LocationService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team to list locations for.")],
        location_type: Annotated[str | None, Parameter(title="Location Type", description="Filter by location type.", required=False)] = None,
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
        return locations_service.to_schema(results, total, filters, schema_type=Location)

    @post(operation_id="CreateLocation", path="/api/teams/{team_id:uuid}/locations")
    async def create_location(
        self,
        locations_service: LocationService,
        current_user: m.User,
        data: LocationCreate,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team to create the location for.")],
    ) -> Location:
        """Create a new location.

        Args:
            locations_service: Location Service
            current_user: Current User
            data: Location Create
            team_id: Team ID

        Returns:
            Location
        """
        obj = data.to_dict()
        obj["team_id"] = team_id
        db_obj = await locations_service.create(obj)
        return locations_service.to_schema(db_obj, schema_type=Location)

    @get(
        operation_id="GetLocation",
        path="/api/teams/{team_id:uuid}/locations/{location_id:uuid}",
        guards=[requires_location_team_membership],
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
        return locations_service.to_schema(db_obj, schema_type=Location)

    @patch(
        operation_id="UpdateLocation",
        path="/api/teams/{team_id:uuid}/locations/{location_id:uuid}",
        guards=[requires_location_team_membership],
    )
    async def update_location(
        self,
        data: LocationUpdate,
        locations_service: LocationService,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team the location belongs to.")],
        location_id: Annotated[UUID, Parameter(title="Location ID", description="The location to update.")],
    ) -> Location:
        """Update a location.

        Args:
            data: Location Update
            locations_service: Location Service
            team_id: Team ID
            location_id: Location ID

        Returns:
            Location
        """
        await locations_service.update(
            item_id=location_id,
            data=data.to_dict(),
        )
        fresh_obj = await locations_service.get_one(id=location_id)
        return locations_service.to_schema(fresh_obj, schema_type=Location)

    @delete(
        operation_id="DeleteLocation",
        path="/api/teams/{team_id:uuid}/locations/{location_id:uuid}",
        guards=[requires_location_team_membership],
    )
    async def delete_location(
        self,
        locations_service: LocationService,
        team_id: Annotated[UUID, Parameter(title="Team ID", description="The team the location belongs to.")],
        location_id: Annotated[UUID, Parameter(title="Location ID", description="The location to delete.")],
    ) -> None:
        """Delete a location.

        Args:
            locations_service: Location Service
            team_id: Team ID
            location_id: Location ID
        """
        _ = await locations_service.delete(location_id)
