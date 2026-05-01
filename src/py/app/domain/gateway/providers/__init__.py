"""Gateway provider registry.

Providers register themselves via the ``register_provider`` decorator.
At runtime, controllers look up a provider by its ``provider_name`` to
dispatch queries against the correct external system.
"""

from __future__ import annotations

from app.domain.gateway.providers._base import GatewayProvider, ProviderResult

PROVIDER_REGISTRY: dict[str, type[GatewayProvider]] = {}


def register_provider(cls: type[GatewayProvider]) -> type[GatewayProvider]:
    """Class decorator that adds a provider to the global registry.

    Args:
        cls: The provider class to register.

    Returns:
        The unmodified provider class.
    """
    PROVIDER_REGISTRY[cls.provider_name] = cls
    return cls


def get_provider(name: str) -> type[GatewayProvider] | None:
    """Look up a registered provider by name.

    Args:
        name: The provider name (matches ``GatewayProvider.provider_name``).

    Returns:
        The provider class, or ``None`` if not registered.
    """
    return PROVIDER_REGISTRY.get(name)


# Import concrete providers so that @register_provider fires at import time.
# These imports must come after PROVIDER_REGISTRY and register_provider are
# defined because the provider modules reference them at decoration time.
from app.domain.gateway.providers._freepbx import FreePBXProvider
from app.domain.gateway.providers._telnyx import TelnyxProvider
from app.domain.gateway.providers._unifi import UnifiProvider

__all__ = (
    "FreePBXProvider",
    "PROVIDER_REGISTRY",
    "GatewayProvider",
    "ProviderResult",
    "TelnyxProvider",
    "UnifiProvider",
    "get_provider",
    "register_provider",
)
