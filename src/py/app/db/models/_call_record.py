from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING
from uuid import UUID

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import ForeignKey, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models._call_record_enums import CallDirection, CallDisposition

if TYPE_CHECKING:
    from app.db.models._connection import Connection
    from app.db.models._team import Team


class CallRecord(UUIDv7AuditBase):
    """A call detail record (CDR) capturing metadata about a phone call."""

    __tablename__ = "call_record"
    __table_args__ = {"comment": "Call detail records for analytics"}

    team_id: Mapped[UUID] = mapped_column(
        ForeignKey("team.id", ondelete="cascade"),
        nullable=False,
        index=True,
    )
    call_date: Mapped[datetime] = mapped_column(nullable=False, index=True)
    caller_id: Mapped[str | None] = mapped_column(String(length=100), nullable=True, default=None)
    source: Mapped[str] = mapped_column(String(length=100), nullable=False)
    destination: Mapped[str] = mapped_column(String(length=100), nullable=False)
    duration: Mapped[int] = mapped_column(default=0, nullable=False)
    billable_seconds: Mapped[int] = mapped_column(default=0, nullable=False)
    direction: Mapped[CallDirection] = mapped_column(
        String(length=20),
        nullable=False,
        index=True,
    )
    disposition: Mapped[CallDisposition] = mapped_column(
        String(length=20),
        nullable=False,
        index=True,
    )
    channel: Mapped[str | None] = mapped_column(String(length=100), nullable=True, default=None)
    unique_id: Mapped[str | None] = mapped_column(String(length=255), nullable=True, default=None)
    recording_url: Mapped[str | None] = mapped_column(String(length=500), nullable=True, default=None)
    cost: Mapped[Decimal | None] = mapped_column(Numeric(10, 4), nullable=True, default=None)
    connection_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("connection.id", ondelete="set null"),
        nullable=True,
        default=None,
        index=True,
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    # Relationships
    team: Mapped[Team] = relationship(
        foreign_keys="CallRecord.team_id",
        innerjoin=True,
        uselist=False,
        lazy="joined",
    )
    connection: Mapped[Connection | None] = relationship(
        foreign_keys="CallRecord.connection_id",
        uselist=False,
        lazy="joined",
    )
