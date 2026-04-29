"""Admin device overview schemas."""

from datetime import datetime
from uuid import UUID

from app.lib.schema import CamelizedBaseStruct


class AdminDeviceStats(CamelizedBaseStruct):
    """Aggregate device statistics for admin overview."""

    total: int
    active: int
    online: int
    offline: int
    error: int
    by_type: dict[str, int]


class AdminDeviceSummary(CamelizedBaseStruct, kw_only=True):
    """Summary device info for admin lists."""

    id: UUID
    name: str
    device_type: str
    status: str
    is_active: bool
    mac_address: str | None = None
    model: str | None = None
    ip_address: str | None = None
    sip_username: str
    owner_email: str | None = None
    team_name: str | None = None
    last_seen_at: datetime | None = None
    created_at: datetime
