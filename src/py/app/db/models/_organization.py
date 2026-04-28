from __future__ import annotations

from advanced_alchemy.base import UUIDv7AuditBase
from advanced_alchemy.mixins import SlugKey
from sqlalchemy import String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column


class Organization(UUIDv7AuditBase, SlugKey):
    """Organization settings and profile.

    Represents the tenant/organization configuration. Typically a singleton
    row per deployment, storing the organization's identity, contact info,
    and extensible settings.
    """

    __tablename__ = "organization"
    __pii_columns__ = {"name", "email", "phone", "website"}

    name: Mapped[str] = mapped_column(nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(String(length=1000), nullable=True, default=None)
    logo_url: Mapped[str | None] = mapped_column(String(length=500), nullable=True, default=None)
    website: Mapped[str | None] = mapped_column(String(length=500), nullable=True, default=None)
    email: Mapped[str | None] = mapped_column(String(length=320), nullable=True, default=None)
    phone: Mapped[str | None] = mapped_column(String(length=20), nullable=True, default=None)
    address_line_1: Mapped[str | None] = mapped_column(String(length=255), nullable=True, default=None)
    address_line_2: Mapped[str | None] = mapped_column(String(length=255), nullable=True, default=None)
    city: Mapped[str | None] = mapped_column(String(length=100), nullable=True, default=None)
    state: Mapped[str | None] = mapped_column(String(length=100), nullable=True, default=None)
    postal_code: Mapped[str | None] = mapped_column(String(length=20), nullable=True, default=None)
    country: Mapped[str | None] = mapped_column(String(length=100), nullable=True, default=None)
    timezone: Mapped[str | None] = mapped_column(String(length=50), nullable=True, default="UTC")
    default_language: Mapped[str | None] = mapped_column(String(length=10), nullable=True, default="en")
    settings: Mapped[dict | None] = mapped_column(JSONB, nullable=True, default=None)
