"""Location domain dependencies."""

from __future__ import annotations

from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.locations.services import LocationService
from app.lib.deps import create_service_provider

provide_locations_service = create_service_provider(
    LocationService,
    load=[selectinload(m.Location.children)],
    error_messages={"duplicate_key": "This location already exists.", "integrity": "Location operation failed."},
)

__all__ = ("provide_locations_service",)
