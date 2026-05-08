"""Analytics domain controllers."""

from app.domain.analytics.controllers._call_analytics import CallAnalyticsController
from app.domain.analytics.controllers._call_record import CallRecordController

__all__ = ("CallAnalyticsController", "CallRecordController")
