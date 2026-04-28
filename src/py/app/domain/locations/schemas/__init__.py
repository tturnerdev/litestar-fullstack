"""Locations domain schemas."""

from app.domain.locations.schemas._location import (
    Location,
    LocationChild,
    LocationCreate,
    LocationUpdate,
)
from app.lib.schema import Message

__all__ = (
    "Location",
    "LocationChild",
    "LocationCreate",
    "LocationUpdate",
    "Message",
)
