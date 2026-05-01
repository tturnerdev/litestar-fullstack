"""Call record schemas."""

from datetime import datetime
from uuid import UUID

import msgspec

from app.lib.schema import CamelizedBaseStruct


class CallRecordList(CamelizedBaseStruct):
    """Call record summary for list views."""

    id: UUID
    team_id: UUID
    call_date: datetime
    caller_id: str | None = None
    source: str = ""
    destination: str = ""
    duration: int = 0
    billable_seconds: int = 0
    direction: str = ""
    disposition: str = ""
    cost: float | None = None
    connection_id: UUID | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class CallRecordDetail(CamelizedBaseStruct):
    """Full call record representation."""

    id: UUID
    team_id: UUID
    call_date: datetime
    caller_id: str | None = None
    source: str = ""
    destination: str = ""
    duration: int = 0
    billable_seconds: int = 0
    direction: str = ""
    disposition: str = ""
    channel: str | None = None
    unique_id: str | None = None
    recording_url: str | None = None
    cost: float | None = None
    connection_id: UUID | None = None
    notes: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class CallRecordCreate(CamelizedBaseStruct):
    """Schema for creating a call record."""

    team_id: UUID
    call_date: datetime
    source: str
    destination: str
    direction: str
    disposition: str
    caller_id: str | None = None
    duration: int = 0
    billable_seconds: int = 0
    channel: str | None = None
    unique_id: str | None = None
    recording_url: str | None = None
    cost: float | None = None
    connection_id: UUID | None = None
    notes: str | None = None


class CallRecordUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a call record."""

    call_date: datetime | msgspec.UnsetType = msgspec.UNSET
    caller_id: str | msgspec.UnsetType | None = msgspec.UNSET
    source: str | msgspec.UnsetType = msgspec.UNSET
    destination: str | msgspec.UnsetType = msgspec.UNSET
    duration: int | msgspec.UnsetType = msgspec.UNSET
    billable_seconds: int | msgspec.UnsetType = msgspec.UNSET
    direction: str | msgspec.UnsetType = msgspec.UNSET
    disposition: str | msgspec.UnsetType = msgspec.UNSET
    channel: str | msgspec.UnsetType | None = msgspec.UNSET
    unique_id: str | msgspec.UnsetType | None = msgspec.UNSET
    recording_url: str | msgspec.UnsetType | None = msgspec.UNSET
    cost: float | msgspec.UnsetType | None = msgspec.UNSET
    connection_id: UUID | msgspec.UnsetType | None = msgspec.UNSET
    notes: str | msgspec.UnsetType | None = msgspec.UNSET


class CallAnalyticsSummary(CamelizedBaseStruct):
    """Aggregate statistics for call analytics."""

    total_calls: int = 0
    answered: int = 0
    missed: int = 0
    voicemail: int = 0
    avg_duration: float = 0.0
    total_duration: int = 0
    avg_billable_seconds: float = 0.0


class CallVolumePoint(CamelizedBaseStruct):
    """A single data point for call volume over time."""

    period: str
    count: int = 0
    answered: int = 0
    missed: int = 0


class ExtensionStats(CamelizedBaseStruct):
    """Per-extension call statistics."""

    extension: str
    total_calls: int = 0
    answered: int = 0
    missed: int = 0
    avg_duration: float = 0.0
