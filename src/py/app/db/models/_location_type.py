"""Location type enum."""

from __future__ import annotations

import enum


class LocationType(str, enum.Enum):
    """Types of locations."""

    ADDRESSED = "ADDRESSED"
    PHYSICAL = "PHYSICAL"
