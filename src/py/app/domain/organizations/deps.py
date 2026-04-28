"""Organization domain dependencies."""

from __future__ import annotations

from app.domain.organizations.services import OrganizationService
from app.lib.deps import create_service_provider

provide_organization_service = create_service_provider(
    OrganizationService,
    error_messages={
        "duplicate_key": "An organization with this name already exists.",
        "integrity": "Organization operation failed.",
    },
)

__all__ = ("provide_organization_service",)
