"""Forwarding rule schemas."""

import datetime as dt
from typing import Annotated
from uuid import UUID

import msgspec
from msgspec import Meta

from app.db.models._voice_enums import ForwardingDestinationType, ForwardingRuleType
from app.lib.schema import CamelizedBaseStruct


class ForwardingRule(CamelizedBaseStruct):
    """Forwarding rule response."""

    id: UUID
    extension_id: UUID
    rule_type: ForwardingRuleType
    destination_type: ForwardingDestinationType
    destination_value: str
    ring_timeout_seconds: int | None = None
    is_active: bool = True
    priority: int = 0
    created_at: dt.datetime | None = None
    updated_at: dt.datetime | None = None


class ForwardingRuleCreate(CamelizedBaseStruct):
    """Forwarding rule create properties."""

    rule_type: ForwardingRuleType
    destination_type: ForwardingDestinationType
    destination_value: Annotated[str, Meta(min_length=1, max_length=255)]
    ring_timeout_seconds: int | None = None
    is_active: bool = True
    priority: int = 0


class ForwardingRuleUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Forwarding rule update properties."""

    rule_type: ForwardingRuleType | msgspec.UnsetType = msgspec.UNSET
    destination_type: ForwardingDestinationType | msgspec.UnsetType = msgspec.UNSET
    destination_value: Annotated[str, Meta(min_length=1, max_length=255)] | msgspec.UnsetType = msgspec.UNSET
    ring_timeout_seconds: int | msgspec.UnsetType | None = msgspec.UNSET
    is_active: bool | msgspec.UnsetType = msgspec.UNSET
    priority: int | msgspec.UnsetType = msgspec.UNSET
