"""Gateway provider base class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from app.db import models as m


@dataclass
class ProviderResult:
    """Result from a provider query."""

    status: str  # "ok", "error", "timeout", "auth_failed", "not_supported"
    data: dict[str, Any] | None = None
    error: str | None = None


class GatewayProvider(ABC):
    """Base class for external data gateway providers.

    Each concrete provider implements queries against a specific external
    system (PBX, carrier, helpdesk, etc.) and declares which domains it
    supports.
    """

    provider_name: ClassVar[str]
    supported_domains: ClassVar[set[str]]  # {"numbers", "extensions", "devices"}

    @abstractmethod
    async def query_number(self, phone_number: str, connection: m.Connection) -> ProviderResult:
        """Query a phone number from this provider.

        Args:
            phone_number: The phone number to look up.
            connection: The connection configuration to use.

        Returns:
            ProviderResult with the query outcome.
        """
        ...

    @abstractmethod
    async def query_extension(self, extension: str, connection: m.Connection) -> ProviderResult:
        """Query an extension from this provider.

        Args:
            extension: The extension number to look up.
            connection: The connection configuration to use.

        Returns:
            ProviderResult with the query outcome.
        """
        ...

    @abstractmethod
    async def query_device(self, mac_address: str, connection: m.Connection) -> ProviderResult:
        """Query a device by MAC address from this provider.

        Args:
            mac_address: The MAC address to look up.
            connection: The connection configuration to use.

        Returns:
            ProviderResult with the query outcome.
        """
        ...

    async def health_check(self, connection: m.Connection) -> tuple[bool, str | None]:
        """Check connectivity to the external system.

        Args:
            connection: The connection configuration to check.

        Returns:
            A tuple of (healthy, error_message).
        """
        return True, None
