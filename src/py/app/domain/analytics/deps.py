"""Analytics domain dependencies."""

from __future__ import annotations

from app.domain.analytics.services import CallRecordService
from app.lib.deps import create_service_provider

provide_call_records_service = create_service_provider(
    CallRecordService,
    error_messages={"duplicate_key": "This call record already exists.", "integrity": "Call record operation failed."},
)

__all__ = ("provide_call_records_service",)
