"""Connections domain dependencies."""

from __future__ import annotations

from app.domain.connections.services import ConnectionService
from app.lib.deps import create_service_provider

provide_connections_service = create_service_provider(
    ConnectionService,
    error_messages={
        "duplicate_key": "A connection with this name already exists for this team.",
        "integrity": "Connection operation failed.",
    },
)

__all__ = ("provide_connections_service",)
