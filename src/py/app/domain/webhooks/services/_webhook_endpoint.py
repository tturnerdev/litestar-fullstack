"""Webhook endpoint service."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx
import structlog
from advanced_alchemy.extensions.litestar import repository, service
from advanced_alchemy.filters import CollectionFilter
from litestar.exceptions import ValidationException

from app.db import models as m
from app.lib.settings import get_settings

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT

logger = structlog.get_logger()

VALIDATION_TIMEOUT_SECONDS = 5

# Private IP networks that should be blocked in non-dev mode
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]


class WebhookEndpointService(service.SQLAlchemyAsyncRepositoryService[m.WebhookEndpoint]):
    """Service for webhook endpoint CRUD operations."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.WebhookEndpoint]):
        """WebhookEndpoint SQLAlchemy Repository."""

        model_type = m.WebhookEndpoint

    repository_type = Repo
    match_fields = ["url"]

    async def to_model_on_create(
        self, data: service.ModelDictT[m.WebhookEndpoint]
    ) -> service.ModelDictT[m.WebhookEndpoint]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            existing = await self.repository.list(
                CollectionFilter(field_name="url", values=[data["url"]]),
            )
            if existing:
                raise ValidationException("A webhook endpoint with this URL already exists.")
        return data

    async def to_model_on_update(self, data: ModelDictT[m.WebhookEndpoint], item_id: Any | None = None, **kwargs: Any) -> ModelDictT[m.WebhookEndpoint]:
        """Validate that no other webhook endpoint with the same URL already exists."""
        data = service.schema_dump(data)
        if service.is_dict(data) and "url" in data:
            existing = await self.repository.list(
                CollectionFilter(field_name="url", values=[data["url"]]),
            )
            if existing and any(str(e.id) != str(item_id) for e in existing):
                raise ValidationException("A webhook endpoint with this URL already exists.")
        return data

    async def create(self, data: dict[str, Any] | m.WebhookEndpoint, **kwargs: Any) -> m.WebhookEndpoint:
        """Create a webhook endpoint with URL validation.

        Args:
            data: The endpoint data to create.
            **kwargs: Additional keyword arguments passed to the repository.

        Returns:
            The created webhook endpoint with validation status set.
        """
        if isinstance(data, dict):
            url = data.get("url", "")
            validation_status = self._validate_url_format(url)
            data["validation_status"] = validation_status
            if validation_status == "valid":
                reachability = await self._check_url_reachability(url)
                data["validation_status"] = reachability
                data["last_validated_at"] = datetime.now(UTC)
            else:
                data["last_validated_at"] = datetime.now(UTC)
        return await super().create(data, **kwargs)

    async def update(self, data: dict[str, Any] | m.WebhookEndpoint, item_id: Any | None = None, **kwargs: Any) -> m.WebhookEndpoint:
        """Update a webhook endpoint, re-validating the URL if it changed.

        Args:
            data: The endpoint data to update.
            item_id: The ID of the endpoint to update.
            **kwargs: Additional keyword arguments passed to the repository.

        Returns:
            The updated webhook endpoint with validation status refreshed if URL changed.
        """
        if isinstance(data, dict) and "url" in data:
            url = data["url"]
            validation_status = self._validate_url_format(url)
            data["validation_status"] = validation_status
            if validation_status == "valid":
                reachability = await self._check_url_reachability(url)
                data["validation_status"] = reachability
                data["last_validated_at"] = datetime.now(UTC)
            else:
                data["last_validated_at"] = datetime.now(UTC)
        return await super().update(data, item_id=item_id, **kwargs)

    @staticmethod
    def _validate_url_format(url: str) -> str:  # noqa: PLR0911
        """Validate the URL format and check for private/reserved addresses.

        Args:
            url: The URL to validate.

        Returns:
            'valid' if the URL passes all checks, or 'invalid_url' with a reason.
        """
        try:
            parsed = urlparse(url)
        except ValueError:
            return "invalid_url"

        if parsed.scheme not in ("http", "https"):
            return "invalid_url"

        if not parsed.hostname:
            return "invalid_url"

        hostname = parsed.hostname.lower()

        settings = get_settings()
        if settings.app.DEV_MODE or settings.app.DEBUG:
            return "valid"

        # Block localhost variants
        if hostname in ("localhost", "0.0.0.0"):  # noqa: S104
            return "invalid_url"

        # Block private IP ranges
        try:
            addr = ipaddress.ip_address(hostname)
            if any(addr in network for network in _PRIVATE_NETWORKS):
                return "invalid_url"
        except ValueError:
            # Not an IP address (it's a hostname) -- that's fine
            pass

        return "valid"

    @staticmethod
    async def _check_url_reachability(url: str) -> str:
        """Send a HEAD request to verify the URL is reachable.

        Args:
            url: The URL to check.

        Returns:
            'valid' if reachable, 'unreachable' otherwise.
        """
        server_error_threshold = 500
        try:
            async with httpx.AsyncClient(timeout=VALIDATION_TIMEOUT_SECONDS) as client:
                response = await client.head(url, follow_redirects=True)
                if response.status_code < server_error_threshold:
                    return "valid"
                await logger.awarning(
                    "Webhook URL returned server error during validation",
                    url=url,
                    status_code=response.status_code,
                )
                return "unreachable"
        except httpx.TimeoutException:
            await logger.awarning("Webhook URL validation timed out", url=url)
            return "unreachable"
        except httpx.RequestError as exc:
            await logger.awarning("Webhook URL unreachable during validation", url=url, error=str(exc))
            return "unreachable"
        except Exception:  # noqa: BLE001
            await logger.aexception("Unexpected error validating webhook URL", url=url)
            return "unreachable"

    async def get_active_endpoints_for_event(self, event_type: str) -> list[m.WebhookEndpoint]:
        """Get all active webhook endpoints subscribed to a specific event type.

        Args:
            event_type: The event type to filter by.

        Returns:
            List of active endpoints that subscribe to this event type.
        """
        all_active = await self.list(
            m.WebhookEndpoint.is_active.is_(True),
        )
        # Filter in Python since ARRAY contains operations vary by DB
        return [
            endpoint for endpoint in all_active
            if event_type in endpoint.events
        ]
