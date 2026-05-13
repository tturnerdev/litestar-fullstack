"""Object storage backend registration.

Builds the configured object-storage backend and registers it with
advanced-alchemy's global storage registry, so that ``StoredObject`` columns can
resolve it by key in both the web application and the background worker.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import structlog
from advanced_alchemy.types.file_object import storages
from advanced_alchemy.types.file_object.backends.obstore import ObstoreBackend

from app.lib.settings import get_settings

if TYPE_CHECKING:
    from app.lib.settings import StorageSettings

__all__ = ("register_storage_backends",)

logger = structlog.get_logger()


def _build_backend(settings: StorageSettings) -> ObstoreBackend:
    backend = settings.BACKEND.lower()
    if backend == "s3":
        kwargs: dict[str, object] = {
            "region": settings.REGION,
            "client_options": {"allow_http": settings.ALLOW_HTTP},
        }
        if settings.ENDPOINT_URL:
            kwargs["endpoint"] = settings.ENDPOINT_URL
        if settings.ACCESS_KEY_ID:
            kwargs["access_key_id"] = settings.ACCESS_KEY_ID
        if settings.SECRET_ACCESS_KEY:
            kwargs["secret_access_key"] = settings.SECRET_ACCESS_KEY
        return ObstoreBackend(key=settings.REGISTRY_KEY, fs=f"s3://{settings.BUCKET}/", **kwargs)
    if backend == "local":
        root = Path(settings.LOCAL_PATH)
        root.mkdir(parents=True, exist_ok=True)
        return ObstoreBackend(key=settings.REGISTRY_KEY, fs=f"file://{root}")
    if backend == "memory":
        return ObstoreBackend(key=settings.REGISTRY_KEY, fs="memory:///")
    msg = f"Unknown STORAGE_BACKEND {settings.BACKEND!r} (expected 's3', 'local', or 'memory')"
    raise ValueError(msg)


def register_storage_backends() -> None:
    """Register the configured object-storage backend.

    Idempotent: safe to call from the web app init, the CLI init, and the
    worker startup path. The backend connection is created lazily, so this does
    not require the object store to be reachable at call time.
    """
    settings = get_settings().storage
    if storages.is_registered(settings.REGISTRY_KEY):
        return
    storages.register_backend(_build_backend(settings))
    logger.debug("registered object storage backend", backend=settings.BACKEND, key=settings.REGISTRY_KEY)
