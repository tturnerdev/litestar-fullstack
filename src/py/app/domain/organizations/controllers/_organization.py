"""Organization Controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar import Controller, get, put
from litestar.di import Provide

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.organizations.deps import provide_organization_service
from app.domain.organizations.guards import requires_admin_role, requires_superuser
from app.domain.organizations.schemas import Organization, OrganizationUpdate
from app.lib.audit import capture_snapshot, log_audit

if TYPE_CHECKING:
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService
    from app.domain.organizations.services import OrganizationService


class OrganizationController(Controller):
    """Organization settings endpoints."""

    tags = ["Organization"]
    path = "/api/organization"
    dependencies = {
        "organization_service": Provide(provide_organization_service),
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(
        operation_id="GetOrganization",
        guards=[requires_admin_role],
    )
    async def get_organization(
        self,
        request: Request[m.User, Token, Any],
        organization_service: OrganizationService,
    ) -> Organization:
        """Get the current organization settings.

        Only accessible by admin and superuser roles.

        Args:
            request: Request with authenticated user.
            organization_service: Organization service.

        Returns:
            The organization settings.
        """
        db_obj = await organization_service.get_one_or_none()
        if db_obj is None:
            db_obj = await organization_service.create({"name": "My Organization"})
        return organization_service.to_schema(db_obj, schema_type=Organization)

    @put(
        operation_id="UpdateOrganization",
        guards=[requires_superuser],
    )
    async def update_organization(
        self,
        request: Request[m.User, Token, Any],
        organization_service: OrganizationService,
        audit_service: AuditLogService,
        data: OrganizationUpdate,
    ) -> Organization:
        """Update the organization settings.

        Only accessible by superusers.

        Args:
            request: Request with authenticated superuser.
            organization_service: Organization service.
            audit_service: Audit Log Service.
            data: Organization update payload.

        Returns:
            The updated organization settings.
        """
        db_obj = await organization_service.get_one_or_none()
        if db_obj is None:
            create_data = data.to_dict()
            if "name" not in create_data:
                create_data["name"] = "My Organization"
            db_obj = await organization_service.create(create_data)
            after = capture_snapshot(db_obj)
            await log_audit(
                audit_service,
                action="organization.settings_update",
                actor_id=request.user.id,
                actor_email=request.user.email,
                target_type="organization",
                target_id=db_obj.id,
                target_label=db_obj.name,
                before=None,
                after=after,
                request=request,
            )
        else:
            before = capture_snapshot(db_obj)
            db_obj = await organization_service.update(
                item_id=db_obj.id,
                data=data.to_dict(),
            )
            after = capture_snapshot(db_obj)
            await log_audit(
                audit_service,
                action="organization.settings_update",
                actor_id=request.user.id,
                actor_email=request.user.email,
                target_type="organization",
                target_id=db_obj.id,
                target_label=db_obj.name,
                before=before,
                after=after,
                request=request,
            )
        return organization_service.to_schema(db_obj, schema_type=Organization)
