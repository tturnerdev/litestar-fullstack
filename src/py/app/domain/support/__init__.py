"""Support domain - helpdesk tickets, messages, attachments."""

from app.domain.support import controllers, schemas, services

__all__ = (
    "controllers",
    "schemas",
    "services",
)
