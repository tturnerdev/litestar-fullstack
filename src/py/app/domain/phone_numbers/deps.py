"""Phone numbers domain dependencies."""

from __future__ import annotations

from sqlalchemy.orm import joinedload

from app.db import models as m
from app.domain.phone_numbers.services import PhoneNumberService
from app.lib.deps import create_service_provider

provide_phone_number_service = create_service_provider(
    PhoneNumberService,
    load=[joinedload(m.PhoneNumber.team)],
    error_messages={
        "duplicate_key": "This phone number already exists.",
        "integrity": "Phone number operation failed.",
    },
)

__all__ = ("provide_phone_number_service",)
