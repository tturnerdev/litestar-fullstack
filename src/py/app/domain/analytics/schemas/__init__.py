"""Analytics domain schemas."""

from app.domain.analytics.schemas._call_record import (
    CallAnalyticsSummary,
    CallRecordCreate,
    CallRecordDetail,
    CallRecordList,
    CallRecordUpdate,
    CallVolumePoint,
    ExtensionStats,
)
from app.lib.schema import Message

__all__ = (
    "CallAnalyticsSummary",
    "CallRecordCreate",
    "CallRecordDetail",
    "CallRecordList",
    "CallRecordUpdate",
    "CallVolumePoint",
    "ExtensionStats",
    "Message",
)
