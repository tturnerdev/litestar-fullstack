"""Admin voice overview schemas."""

from datetime import datetime
from uuid import UUID

from app.lib.schema import CamelizedBaseStruct


class AdminVoiceStats(CamelizedBaseStruct):
    """Aggregate voice statistics for admin overview."""

    total_phone_numbers: int
    active_phone_numbers: int
    total_extensions: int
    active_extensions: int
    active_dnd: int
    by_number_type: dict[str, int]


class AdminPhoneNumberSummary(CamelizedBaseStruct, kw_only=True):
    """Summary phone number info for admin lists."""

    id: UUID
    number: str
    label: str | None = None
    number_type: str
    is_active: bool
    caller_id_name: str | None = None
    owner_email: str | None = None
    team_name: str | None = None
    created_at: datetime


class AdminExtensionSummary(CamelizedBaseStruct, kw_only=True):
    """Summary extension info for admin lists."""

    id: UUID
    extension_number: str
    display_name: str
    is_active: bool
    owner_email: str | None = None
    phone_number: str | None = None
    created_at: datetime
