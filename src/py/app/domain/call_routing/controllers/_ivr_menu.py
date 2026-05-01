"""IVR Menu Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from sqlalchemy.orm import selectinload

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.call_routing.deps import provide_ivr_menu_options_service
from app.domain.call_routing.guards import requires_call_routing_access
from app.domain.teams.guards import requires_feature_permission
from app.domain.call_routing.schemas import (
    IvrMenu,
    IvrMenuCreate,
    IvrMenuOption,
    IvrMenuOptionCreate,
    IvrMenuOptionUpdate,
    IvrMenuUpdate,
)
from app.domain.call_routing.services import IvrMenuOptionService, IvrMenuService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService


class IvrMenuController(Controller):
    """IVR Menus."""

    tags = ["Call Routing - IVR Menus"]
    dependencies = create_service_dependencies(
        IvrMenuService,
        key="ivr_menus_service",
        load=[selectinload(m.IvrMenu.options)],
        filters={
            "id_filter": UUID,
            "search": "name",
            "pagination_type": "limit_offset",
            "pagination_size": 20,
            "created_at": True,
            "updated_at": True,
            "sort_field": "name",
            "sort_order": "asc",
        },
    ) | {
        "audit_service": Provide(provide_audit_log_service),
        "ivr_menu_options_service": Provide(provide_ivr_menu_options_service),
    }

    @get(
        operation_id="ListIvrMenus",
        path="/api/ivr-menus",
        guards=[requires_feature_permission("call_routing", "view"), requires_call_routing_access],
    )
    async def list_ivr_menus(
        self,
        ivr_menus_service: IvrMenuService,
        current_user: m.User,
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[IvrMenu]:
        """List IVR menus.

        Args:
            ivr_menus_service: IVR Menu Service
            current_user: Current User
            filters: Filters

        Returns:
            OffsetPagination[IvrMenu]
        """
        results, total = await ivr_menus_service.list_and_count(*filters)
        return ivr_menus_service.to_schema(results, total, filters, schema_type=IvrMenu)

    @post(
        operation_id="CreateIvrMenu",
        path="/api/ivr-menus",
        guards=[requires_feature_permission("call_routing", "edit"), requires_call_routing_access],
    )
    async def create_ivr_menu(
        self,
        request: Request[m.User, Token, Any],
        ivr_menus_service: IvrMenuService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: IvrMenuCreate,
    ) -> IvrMenu:
        """Create a new IVR menu.

        Args:
            request: The current request
            ivr_menus_service: IVR Menu Service
            audit_service: Audit Log Service
            current_user: Current User
            data: IVR Menu Create

        Returns:
            IvrMenu
        """
        obj = data.to_dict()
        obj["team_id"] = current_user.team_id if hasattr(current_user, "team_id") else None
        db_obj = await ivr_menus_service.create(obj)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="call_routing.ivr_menu.create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ivr_menu",
            target_id=db_obj.id,
            target_label=db_obj.name,
            before=None,
            after=after,
            request=request,
        )
        return ivr_menus_service.to_schema(db_obj, schema_type=IvrMenu)

    @get(
        operation_id="GetIvrMenu",
        path="/api/ivr-menus/{ivr_menu_id:uuid}",
        guards=[requires_feature_permission("call_routing", "view"), requires_call_routing_access],
    )
    async def get_ivr_menu(
        self,
        ivr_menus_service: IvrMenuService,
        ivr_menu_id: Annotated[UUID, Parameter(title="IVR Menu ID", description="The IVR menu to retrieve.")],
    ) -> IvrMenu:
        """Get details about an IVR menu.

        Args:
            ivr_menus_service: IVR Menu Service
            ivr_menu_id: IVR Menu ID

        Returns:
            IvrMenu
        """
        db_obj = await ivr_menus_service.get(ivr_menu_id)
        return ivr_menus_service.to_schema(db_obj, schema_type=IvrMenu)

    @patch(
        operation_id="UpdateIvrMenu",
        path="/api/ivr-menus/{ivr_menu_id:uuid}",
        guards=[requires_feature_permission("call_routing", "edit"), requires_call_routing_access],
    )
    async def update_ivr_menu(
        self,
        request: Request[m.User, Token, Any],
        data: IvrMenuUpdate,
        ivr_menus_service: IvrMenuService,
        audit_service: AuditLogService,
        current_user: m.User,
        ivr_menu_id: Annotated[UUID, Parameter(title="IVR Menu ID", description="The IVR menu to update.")],
    ) -> IvrMenu:
        """Update an IVR menu.

        Args:
            request: The current request
            data: IVR Menu Update
            ivr_menus_service: IVR Menu Service
            audit_service: Audit Log Service
            current_user: Current User
            ivr_menu_id: IVR Menu ID

        Returns:
            IvrMenu
        """
        before = capture_snapshot(await ivr_menus_service.get(ivr_menu_id))
        await ivr_menus_service.update(item_id=ivr_menu_id, data=data.to_dict())
        fresh_obj = await ivr_menus_service.get_one(id=ivr_menu_id)
        after = capture_snapshot(fresh_obj)
        await log_audit(
            audit_service,
            action="call_routing.ivr_menu.update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ivr_menu",
            target_id=ivr_menu_id,
            target_label=fresh_obj.name,
            before=before,
            after=after,
            request=request,
        )
        return ivr_menus_service.to_schema(fresh_obj, schema_type=IvrMenu)

    @delete(
        operation_id="DeleteIvrMenu",
        path="/api/ivr-menus/{ivr_menu_id:uuid}",
        return_dto=None,
        guards=[requires_feature_permission("call_routing", "edit"), requires_call_routing_access],
    )
    async def delete_ivr_menu(
        self,
        request: Request[m.User, Token, Any],
        ivr_menus_service: IvrMenuService,
        audit_service: AuditLogService,
        current_user: m.User,
        ivr_menu_id: Annotated[UUID, Parameter(title="IVR Menu ID", description="The IVR menu to delete.")],
    ) -> None:
        """Delete an IVR menu.

        Args:
            request: The current request
            ivr_menus_service: IVR Menu Service
            audit_service: Audit Log Service
            current_user: Current User
            ivr_menu_id: IVR Menu ID
        """
        db_obj = await ivr_menus_service.get(ivr_menu_id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.name
        await ivr_menus_service.delete(ivr_menu_id)
        await log_audit(
            audit_service,
            action="call_routing.ivr_menu.delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ivr_menu",
            target_id=ivr_menu_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )

    # --- IVR Menu Options ---

    @get(
        operation_id="ListIvrMenuOptions",
        path="/api/ivr-menus/{ivr_menu_id:uuid}/options",
        guards=[requires_feature_permission("call_routing", "view"), requires_call_routing_access],
    )
    async def list_options(
        self,
        ivr_menus_service: IvrMenuService,
        ivr_menu_options_service: IvrMenuOptionService,
        ivr_menu_id: Annotated[UUID, Parameter(title="IVR Menu ID", description="The IVR menu.")],
    ) -> list[IvrMenuOption]:
        """List options for an IVR menu.

        Args:
            ivr_menus_service: IVR Menu Service
            ivr_menu_options_service: IVR Menu Option Service
            ivr_menu_id: IVR Menu ID

        Returns:
            list[IvrMenuOption]
        """
        await ivr_menus_service.get(ivr_menu_id)
        results = await ivr_menu_options_service.list(m.IvrMenuOption.ivr_menu_id == ivr_menu_id)
        return ivr_menu_options_service.to_schema(results, schema_type=IvrMenuOption)

    @post(
        operation_id="CreateIvrMenuOption",
        path="/api/ivr-menus/{ivr_menu_id:uuid}/options",
        guards=[requires_feature_permission("call_routing", "edit"), requires_call_routing_access],
    )
    async def create_option(
        self,
        request: Request[m.User, Token, Any],
        ivr_menus_service: IvrMenuService,
        ivr_menu_options_service: IvrMenuOptionService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: IvrMenuOptionCreate,
        ivr_menu_id: Annotated[UUID, Parameter(title="IVR Menu ID", description="The IVR menu.")],
    ) -> IvrMenuOption:
        """Add an option to an IVR menu.

        Args:
            request: The current request
            ivr_menus_service: IVR Menu Service
            ivr_menu_options_service: IVR Menu Option Service
            audit_service: Audit Log Service
            current_user: Current User
            data: IVR Menu Option Create
            ivr_menu_id: IVR Menu ID

        Returns:
            IvrMenuOption
        """
        menu = await ivr_menus_service.get(ivr_menu_id)
        obj = data.to_dict()
        obj["ivr_menu_id"] = ivr_menu_id
        db_obj = await ivr_menu_options_service.create(obj)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="call_routing.ivr_menu_option.create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ivr_menu_option",
            target_id=db_obj.id,
            target_label=f"{menu.name}:{db_obj.digit}",
            before=None,
            after=after,
            request=request,
        )
        return ivr_menu_options_service.to_schema(db_obj, schema_type=IvrMenuOption)

    @patch(
        operation_id="UpdateIvrMenuOption",
        path="/api/ivr-menus/{ivr_menu_id:uuid}/options/{option_id:uuid}",
        guards=[requires_feature_permission("call_routing", "edit"), requires_call_routing_access],
    )
    async def update_option(
        self,
        request: Request[m.User, Token, Any],
        ivr_menus_service: IvrMenuService,
        ivr_menu_options_service: IvrMenuOptionService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: IvrMenuOptionUpdate,
        ivr_menu_id: Annotated[UUID, Parameter(title="IVR Menu ID", description="The IVR menu.")],
        option_id: Annotated[UUID, Parameter(title="Option ID", description="The option to update.")],
    ) -> IvrMenuOption:
        """Update an IVR menu option.

        Args:
            request: The current request
            ivr_menus_service: IVR Menu Service
            ivr_menu_options_service: IVR Menu Option Service
            audit_service: Audit Log Service
            current_user: Current User
            data: IVR Menu Option Update
            ivr_menu_id: IVR Menu ID
            option_id: Option ID

        Returns:
            IvrMenuOption
        """
        await ivr_menus_service.get(ivr_menu_id)
        before = capture_snapshot(await ivr_menu_options_service.get_one(id=option_id, ivr_menu_id=ivr_menu_id))
        await ivr_menu_options_service.update(item_id=option_id, data=data.to_dict())
        fresh_obj = await ivr_menu_options_service.get_one(id=option_id)
        after = capture_snapshot(fresh_obj)
        await log_audit(
            audit_service,
            action="call_routing.ivr_menu_option.update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ivr_menu_option",
            target_id=option_id,
            target_label=f"digit:{fresh_obj.digit}",
            before=before,
            after=after,
            request=request,
        )
        return ivr_menu_options_service.to_schema(fresh_obj, schema_type=IvrMenuOption)

    @delete(
        operation_id="DeleteIvrMenuOption",
        path="/api/ivr-menus/{ivr_menu_id:uuid}/options/{option_id:uuid}",
        return_dto=None,
        guards=[requires_feature_permission("call_routing", "edit"), requires_call_routing_access],
    )
    async def delete_option(
        self,
        request: Request[m.User, Token, Any],
        ivr_menus_service: IvrMenuService,
        ivr_menu_options_service: IvrMenuOptionService,
        audit_service: AuditLogService,
        current_user: m.User,
        ivr_menu_id: Annotated[UUID, Parameter(title="IVR Menu ID", description="The IVR menu.")],
        option_id: Annotated[UUID, Parameter(title="Option ID", description="The option to delete.")],
    ) -> None:
        """Delete an IVR menu option.

        Args:
            request: The current request
            ivr_menus_service: IVR Menu Service
            ivr_menu_options_service: IVR Menu Option Service
            audit_service: Audit Log Service
            current_user: Current User
            ivr_menu_id: IVR Menu ID
            option_id: Option ID
        """
        await ivr_menus_service.get(ivr_menu_id)
        db_obj = await ivr_menu_options_service.get_one(id=option_id, ivr_menu_id=ivr_menu_id)
        before = capture_snapshot(db_obj)
        target_label = f"digit:{db_obj.digit}"
        await ivr_menu_options_service.delete(option_id)
        await log_audit(
            audit_service,
            action="call_routing.ivr_menu_option.delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="ivr_menu_option",
            target_id=option_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )
