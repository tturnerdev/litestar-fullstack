"""Notification preference schemas."""

from uuid import UUID

import msgspec

from app.lib.schema import CamelizedBaseStruct


class NotificationPreference(CamelizedBaseStruct):
    """Notification preference response."""

    id: UUID
    user_id: UUID
    email_enabled: bool
    categories: dict[str, bool]


class NotificationPreferenceUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Notification preference update properties."""

    email_enabled: bool | msgspec.UnsetType = msgspec.UNSET
    categories: dict[str, bool] | msgspec.UnsetType = msgspec.UNSET
