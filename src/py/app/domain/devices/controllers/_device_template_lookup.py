"""Device template lookup controller (non-admin, authenticated)."""

from __future__ import annotations

from typing import Any

from litestar import Controller, get
from litestar.di import Provide
from litestar.exceptions import NotFoundException

from app.domain.admin.schemas import DeviceTemplateLookup
from app.domain.admin.services import DeviceTemplateService
from app.lib.deps import create_service_provider

provide_device_template_service = create_service_provider(
    DeviceTemplateService,
    error_messages={
        "duplicate_key": "Device template already exists.",
        "integrity": "Device template operation failed.",
    },
)


class DeviceTemplateLookupController(Controller):
    """Device template lookup for authenticated users."""

    tags = ["Devices"]
    path = "/api/devices/templates"
    dependencies = {
        "template_service": Provide(provide_device_template_service),
    }

    @get(operation_id="LookupDeviceTemplate", path="/lookup")
    async def lookup_template(
        self,
        template_service: DeviceTemplateService,
        manufacturer: str,
        model: str,
    ) -> DeviceTemplateLookup:
        """Look up a device template by manufacturer and model.

        Args:
            template_service: DeviceTemplate Service
            manufacturer: Device manufacturer name.
            model: Device model name.

        Returns:
            The matching device template wireframe data.

        Raises:
            NotFoundException: If no template matches the given manufacturer and model.
        """
        db_obj = await template_service.get_by_manufacturer_model(manufacturer, model)
        if db_obj is None:
            raise NotFoundException(
                detail=f"No template found for manufacturer={manufacturer!r}, model={model!r}",
            )
        return DeviceTemplateLookup(
            id=db_obj.id,
            manufacturer=db_obj.manufacturer,
            model=db_obj.model,
            display_name=db_obj.display_name,
            device_type=db_obj.device_type,
            wireframe_data=db_obj.wireframe_data,
            provisioning_template=db_obj.provisioning_template,
            template_variables=db_obj.template_variables,
            image_url=db_obj.image_url,
        )
