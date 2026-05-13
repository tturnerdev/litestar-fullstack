"""Attachments domain - file uploads backed by object storage."""

from app.domain.attachments import controllers, schemas, services

__all__ = (
    "controllers",
    "schemas",
    "services",
)
