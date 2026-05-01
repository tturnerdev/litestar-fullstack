"""Admin device template schemas."""

from datetime import datetime
from typing import Any
from uuid import UUID

import msgspec

from app.lib.schema import CamelizedBaseStruct


class DeviceTemplateList(CamelizedBaseStruct, kw_only=True):
    """Summary device template info for admin lists."""

    id: UUID
    manufacturer: str
    model: str
    display_name: str
    device_type: str
    is_active: bool
    image_url: str | None = None
    created_at: datetime
    updated_at: datetime


class DeviceTemplateDetail(CamelizedBaseStruct, kw_only=True):
    """Full device template representation."""

    id: UUID
    manufacturer: str
    model: str
    display_name: str
    device_type: str
    wireframe_data: dict[str, Any]
    provisioning_template: str | None = None
    template_variables: dict[str, Any] | None = None
    image_url: str | None = None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class DeviceTemplateCreate(CamelizedBaseStruct):
    """Schema for creating a device template."""

    manufacturer: str
    model: str
    display_name: str
    device_type: str
    wireframe_data: dict[str, Any]
    provisioning_template: str | None = None
    template_variables: dict[str, Any] | None = None
    image_url: str | None = None
    is_active: bool = True


class DeviceTemplateUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Schema for updating a device template."""

    manufacturer: str | msgspec.UnsetType = msgspec.UNSET
    model: str | msgspec.UnsetType = msgspec.UNSET
    display_name: str | msgspec.UnsetType = msgspec.UNSET
    device_type: str | msgspec.UnsetType = msgspec.UNSET
    wireframe_data: dict[str, Any] | msgspec.UnsetType = msgspec.UNSET
    provisioning_template: str | msgspec.UnsetType | None = msgspec.UNSET
    template_variables: dict[str, Any] | msgspec.UnsetType | None = msgspec.UNSET
    image_url: str | msgspec.UnsetType | None = msgspec.UNSET
    is_active: bool | msgspec.UnsetType = msgspec.UNSET


class DeviceTemplateLookup(CamelizedBaseStruct, kw_only=True):
    """Wireframe data returned from template lookup."""

    id: UUID
    manufacturer: str
    model: str
    display_name: str
    device_type: str
    wireframe_data: dict[str, Any]
    provisioning_template: str | None = None
    template_variables: dict[str, Any] | None = None
    image_url: str | None = None
