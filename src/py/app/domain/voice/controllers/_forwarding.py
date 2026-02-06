"""Forwarding Rule Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from litestar import Controller, delete, get, patch, post, put
from litestar.di import Provide
from litestar.params import Dependency, Parameter

from app.db import models as m
from app.domain.voice.deps import provide_extensions_service
from app.domain.voice.guards import requires_extension_ownership
from app.domain.voice.schemas import ForwardingRule, ForwardingRuleCreate, ForwardingRuleUpdate
from app.domain.voice.services import ForwardingRuleService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination

    from app.domain.voice.services import ExtensionService


class ForwardingController(Controller):
    """Call Forwarding Rules."""

    tags = ["Voice - Forwarding"]
    guards = [requires_extension_ownership]
    dependencies = {
        "extensions_service": Provide(provide_extensions_service),
        **create_service_dependencies(
            ForwardingRuleService,
            key="forwarding_rules_service",
            filters={
                "id_filter": UUID,
                "pagination_type": "limit_offset",
                "pagination_size": 50,
                "created_at": True,
                "updated_at": True,
                "sort_field": "priority",
                "sort_order": "asc",
            },
        ),
    }

    @get(operation_id="ListForwardingRules", path="/api/voice/extensions/{ext_id:uuid}/forwarding")
    async def list_forwarding_rules(
        self,
        extensions_service: ExtensionService,
        forwarding_rules_service: ForwardingRuleService,
        current_user: m.User,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
        filters: Annotated[list[FilterTypes], Dependency(skip_validation=True)],
    ) -> OffsetPagination[ForwardingRule]:
        """Get all forwarding rules."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        results, total = await forwarding_rules_service.list_and_count(
            *filters,
            m.ForwardingRule.extension_id == ext_id,
        )
        return forwarding_rules_service.to_schema(results, total, filters, schema_type=ForwardingRule)

    @post(operation_id="CreateForwardingRule", path="/api/voice/extensions/{ext_id:uuid}/forwarding")
    async def create_forwarding_rule(
        self,
        extensions_service: ExtensionService,
        forwarding_rules_service: ForwardingRuleService,
        current_user: m.User,
        data: ForwardingRuleCreate,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
    ) -> ForwardingRule:
        """Add a forwarding rule."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        obj = data.to_dict()
        obj["extension_id"] = ext_id
        db_obj = await forwarding_rules_service.create(obj)
        return forwarding_rules_service.to_schema(db_obj, schema_type=ForwardingRule)

    @put(operation_id="SetForwardingRules", path="/api/voice/extensions/{ext_id:uuid}/forwarding")
    async def set_forwarding_rules(
        self,
        extensions_service: ExtensionService,
        forwarding_rules_service: ForwardingRuleService,
        current_user: m.User,
        data: list[ForwardingRuleCreate],
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
    ) -> list[ForwardingRule]:
        """Bulk replace all rules."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        # Delete existing rules
        existing, _ = await forwarding_rules_service.list_and_count(
            m.ForwardingRule.extension_id == ext_id,
        )
        for rule in existing:
            await forwarding_rules_service.delete(rule.id)
        # Create new rules
        results = []
        for rule_data in data:
            obj = rule_data.to_dict()
            obj["extension_id"] = ext_id
            db_obj = await forwarding_rules_service.create(obj)
            results.append(forwarding_rules_service.to_schema(db_obj, schema_type=ForwardingRule))
        return results

    @patch(
        operation_id="UpdateForwardingRule",
        path="/api/voice/extensions/{ext_id:uuid}/forwarding/{rule_id:uuid}",
    )
    async def update_forwarding_rule(
        self,
        extensions_service: ExtensionService,
        forwarding_rules_service: ForwardingRuleService,
        current_user: m.User,
        data: ForwardingRuleUpdate,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
        rule_id: Annotated[UUID, Parameter(title="Rule ID", description="The forwarding rule to update.")],
    ) -> ForwardingRule:
        """Update a forwarding rule."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        db_obj = await forwarding_rules_service.get_one(id=rule_id, extension_id=ext_id)
        db_obj = await forwarding_rules_service.update(item_id=db_obj.id, data=data.to_dict())
        return forwarding_rules_service.to_schema(db_obj, schema_type=ForwardingRule)

    @delete(
        operation_id="DeleteForwardingRule",
        path="/api/voice/extensions/{ext_id:uuid}/forwarding/{rule_id:uuid}",
        return_dto=None,
    )
    async def delete_forwarding_rule(
        self,
        extensions_service: ExtensionService,
        forwarding_rules_service: ForwardingRuleService,
        current_user: m.User,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
        rule_id: Annotated[UUID, Parameter(title="Rule ID", description="The forwarding rule to delete.")],
    ) -> None:
        """Remove a forwarding rule."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        await forwarding_rules_service.get_one(id=rule_id, extension_id=ext_id)
        await forwarding_rules_service.delete(rule_id)
