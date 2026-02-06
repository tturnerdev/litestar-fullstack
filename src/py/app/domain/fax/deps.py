"""Fax domain dependencies."""

from __future__ import annotations

from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.fax.services import FaxEmailRouteService, FaxMessageService, FaxNumberService
from app.lib.deps import create_service_provider

provide_fax_numbers_service = create_service_provider(
    FaxNumberService,
    load=[selectinload(m.FaxNumber.email_routes)],
    error_messages={"duplicate_key": "This fax number already exists.", "integrity": "Fax number operation failed."},
)

provide_fax_email_routes_service = create_service_provider(
    FaxEmailRouteService,
    load=[selectinload(m.FaxEmailRoute.fax_number)],
    error_messages={"duplicate_key": "This email route already exists.", "integrity": "Email route operation failed."},
)

provide_fax_messages_service = create_service_provider(
    FaxMessageService,
    load=[selectinload(m.FaxMessage.fax_number)],
    error_messages={"duplicate_key": "This fax message already exists.", "integrity": "Fax message operation failed."},
)

__all__ = (
    "provide_fax_email_routes_service",
    "provide_fax_messages_service",
    "provide_fax_numbers_service",
)
