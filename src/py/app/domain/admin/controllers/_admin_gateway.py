"""Admin Gateway Settings Controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import msgspec
import structlog
from litestar import Controller, get, put
from litestar.di import Provide

from app.domain.accounts.guards import requires_superuser
from app.domain.admin.deps import provide_audit_log_service
from app.domain.admin.schemas._admin_gateway import AdminGatewaySettings, AdminGatewaySettingsUpdate
from app.lib.audit import log_audit
from app.lib.settings import get_settings

if TYPE_CHECKING:
    from litestar import Request
    from litestar.security.jwt import Token

    from app.db import models as m
    from app.domain.admin.services import AuditLogService

logger = structlog.get_logger()


class AdminGatewayController(Controller):
    """Admin gateway settings endpoints."""

    tags = ["Admin"]
    path = "/api/admin/gateway"
    guards = [requires_superuser]
    dependencies = {
        "audit_service": Provide(provide_audit_log_service),
    }

    @get(operation_id="GetAdminGatewaySettings", path="/settings")
    async def get_gateway_settings(
        self,
        request: Request[m.User, Token, Any],
    ) -> AdminGatewaySettings:
        """Get current gateway settings.

        Args:
            request: Request with authenticated superuser.

        Returns:
            Current gateway settings.
        """
        settings = get_settings()
        return AdminGatewaySettings(
            default_timeout=settings.gateway.DEFAULT_TIMEOUT,
            default_cache_ttl=settings.gateway.DEFAULT_CACHE_TTL,
        )

    @put(operation_id="UpdateAdminGatewaySettings", path="/settings")
    async def update_gateway_settings(
        self,
        request: Request[m.User, Token, Any],
        audit_service: AuditLogService,
        data: AdminGatewaySettingsUpdate,
    ) -> AdminGatewaySettings:
        """Update gateway settings.

        Note: These changes are applied to the in-memory settings instance
        and persist for the lifetime of the running process. To make them
        permanent across restarts, update the corresponding environment
        variables (GATEWAY_DEFAULT_TIMEOUT, GATEWAY_DEFAULT_CACHE_TTL).

        Args:
            request: Request with authenticated superuser.
            data: The settings update payload.

        Returns:
            Updated gateway settings.
        """
        settings = get_settings()

        if data.default_timeout is not msgspec.UNSET:
            settings.gateway.DEFAULT_TIMEOUT = data.default_timeout

        if data.default_cache_ttl is not msgspec.UNSET:
            settings.gateway.DEFAULT_CACHE_TTL = data.default_cache_ttl

        await logger.ainfo(
            "Gateway settings updated",
            actor=request.user.email,
            timeout=settings.gateway.DEFAULT_TIMEOUT,
            cache_ttl=settings.gateway.DEFAULT_CACHE_TTL,
        )

        await log_audit(
            audit_service,
            action="admin.gateway_settings.updated",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="system_settings",
            target_label="Gateway Settings",
            after={
                "default_timeout": settings.gateway.DEFAULT_TIMEOUT,
                "default_cache_ttl": settings.gateway.DEFAULT_CACHE_TTL,
            },
            request=request,
        )

        return AdminGatewaySettings(
            default_timeout=settings.gateway.DEFAULT_TIMEOUT,
            default_cache_ttl=settings.gateway.DEFAULT_CACHE_TTL,
        )
