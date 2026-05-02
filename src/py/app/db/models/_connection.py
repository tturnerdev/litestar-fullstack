from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._connection_enums import ConnectionAuthType, ConnectionStatus, ConnectionType

if TYPE_CHECKING:
    from app.db.models._device import Device
    from app.db.models._team import Team


class Connection(UUIDv7AuditBase):
    """An external data source connection (PBX, helpdesk, carrier, etc.)."""

    __tablename__ = "connection"
    __table_args__ = {"comment": "External data source connections"}

    team_id: Mapped[UUID] = mapped_column(
        ForeignKey("team.id", ondelete="cascade"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(length=255), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    connection_type: Mapped[ConnectionType] = mapped_column(
        String(length=50),
        default=ConnectionType.OTHER,
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(length=100), nullable=False)
    host: Mapped[str | None] = mapped_column(String(length=500), nullable=True, default=None)
    port: Mapped[int | None] = mapped_column(nullable=True, default=None)
    auth_type: Mapped[ConnectionAuthType] = mapped_column(
        String(length=50),
        default=ConnectionAuthType.NONE,
        nullable=False,
    )
    credentials: Mapped[dict | None] = mapped_column(JSONB, nullable=True, default=None)
    settings: Mapped[dict | None] = mapped_column(JSONB, nullable=True, default=None)
    status: Mapped[ConnectionStatus] = mapped_column(
        String(length=50),
        default=ConnectionStatus.UNKNOWN,
        nullable=False,
        index=True,
    )
    last_health_check: Mapped[datetime | None] = mapped_column(nullable=True, default=None)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    is_enabled: Mapped[bool] = mapped_column(default=True, nullable=False)

    # Relationships
    team: Mapped[Team] = relationship(
        foreign_keys="Connection.team_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
    devices: Mapped[list[Device]] = relationship(
        foreign_keys="Device.connection_id",
        uselist=True,
        lazy="noload",
        viewonly=True,
    )
