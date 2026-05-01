"""Analytics domain controllers."""

from app.domain.analytics.controllers._call_record import CallRecordController
from app.domain.analytics.controllers._call_analytics import CallAnalyticsController

__all__ = ("CallAnalyticsController", "CallRecordController")
