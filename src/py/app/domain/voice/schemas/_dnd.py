"""Do Not Disturb schemas."""

from datetime import time
from uuid import UUID

import msgspec

from app.db.models._voice_enums import DndMode
from app.lib.schema import CamelizedBaseStruct


class DndSettings(CamelizedBaseStruct):
    """DND settings response."""

    id: UUID
    extension_id: UUID
    is_enabled: bool = False
    mode: DndMode = DndMode.OFF
    schedule_start: time | None = None
    schedule_end: time | None = None
    schedule_days: list[int] | None = None
    allow_list: list[str] | None = None


class DndSettingsUpdate(CamelizedBaseStruct, omit_defaults=True):
    """DND settings update properties."""

    is_enabled: bool | msgspec.UnsetType = msgspec.UNSET
    mode: DndMode | msgspec.UnsetType = msgspec.UNSET
    schedule_start: time | msgspec.UnsetType | None = msgspec.UNSET
    schedule_end: time | msgspec.UnsetType | None = msgspec.UNSET
    schedule_days: list[int] | msgspec.UnsetType | None = msgspec.UNSET
    allow_list: list[str] | msgspec.UnsetType | None = msgspec.UNSET


class DndToggleResponse(CamelizedBaseStruct):
    """DND toggle response."""

    is_enabled: bool
