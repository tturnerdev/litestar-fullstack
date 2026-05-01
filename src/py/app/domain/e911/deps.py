"""E911 domain dependencies."""

from __future__ import annotations

from sqlalchemy.orm import joinedload

from app.db import models as m
from app.domain.e911.services import E911RegistrationService
from app.lib.deps import create_service_provider

provide_e911_registration_service = create_service_provider(
    E911RegistrationService,
    load=[
        joinedload(m.E911Registration.phone_number),
        joinedload(m.E911Registration.location),
    ],
    error_messages={
        "duplicate_key": "An E911 registration already exists for this phone number.",
        "integrity": "E911 registration operation failed.",
    },
)

__all__ = ("provide_e911_registration_service",)
