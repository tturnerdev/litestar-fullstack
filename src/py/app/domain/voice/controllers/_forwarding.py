"""Forwarding Rule Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post, put
from litestar.di import Provide
from litestar.params import Dependency, Parameter

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.voice.deps import provide_extensions_service
from app.domain.voice.guards import requires_extension_ownership
from app.domain.voice.schemas import ForwardingRule, ForwardingRuleCreate, ForwardingRuleUpdate
from app.domain.voice.services import ForwardingRuleService
from app.lib.audit import capture_snapshot, log_audit
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from advanced_alchemy.filters import FilterTypes
    from advanced_alchemy.service.pagination import OffsetPagination
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService
    from app.domain.voice.services import ExtensionService


class ForwardingController(Controller):
    """Call Forwarding Rules."""

    tags = ["Voice - Forwarding"]
    guards = [requires_extension_ownership]
    dependencies = {
        "extensions_service": Provide(provide_extensions_service),
        "audit_service": Provide(provide_audit_log_service),
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
        request: Request[m.User, Token, Any],
        extensions_service: ExtensionService,
        forwarding_rules_service: ForwardingRuleService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: ForwardingRuleCreate,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
    ) -> ForwardingRule:
        """Add a forwarding rule."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        obj = data.to_dict()
        obj["extension_id"] = ext_id
        db_obj = await forwarding_rules_service.create(obj)
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="voice.forwarding_rule_create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="forwarding_rule",
            target_id=db_obj.id,
            target_label=db_obj.destination_value,
            before=None,
            after=after,
            request=request,
        )
        return forwarding_rules_service.to_schema(db_obj, schema_type=ForwardingRule)

    @put(operation_id="SetForwardingRules", path="/api/voice/extensions/{ext_id:uuid}/forwarding")
    async def set_forwarding_rules(
        self,
        request: Request[m.User, Token, Any],
        extensions_service: ExtensionService,
        forwarding_rules_service: ForwardingRuleService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: list[ForwardingRuleCreate],
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
    ) -> list[ForwardingRule]:
        """Bulk replace all rules."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        # Capture before state
        existing, _ = await forwarding_rules_service.list_and_count(
            m.ForwardingRule.extension_id == ext_id,
        )
        before_rules = [capture_snapshot(rule) for rule in existing]
        # Delete existing rules
        for rule in existing:
            await forwarding_rules_service.delete(rule.id)
        # Create new rules
        results = []
        after_rules = []
        for rule_data in data:
            obj = rule_data.to_dict()
            obj["extension_id"] = ext_id
            db_obj = await forwarding_rules_service.create(obj)
            after_rules.append(capture_snapshot(db_obj))
            results.append(forwarding_rules_service.to_schema(db_obj, schema_type=ForwardingRule))
        await log_audit(
            audit_service,
            action="voice.forwarding_rule_bulk_replace",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="forwarding_rule",
            target_id=ext_id,
            target_label=f"extension:{ext_id}",
            before={"rules": before_rules},
            after={"rules": after_rules},
            request=request,
        )
        return results

    @patch(
        operation_id="UpdateForwardingRule",
        path="/api/voice/extensions/{ext_id:uuid}/forwarding/{rule_id:uuid}",
    )
    async def update_forwarding_rule(
        self,
        request: Request[m.User, Token, Any],
        extensions_service: ExtensionService,
        forwarding_rules_service: ForwardingRuleService,
        audit_service: AuditLogService,
        current_user: m.User,
        data: ForwardingRuleUpdate,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
        rule_id: Annotated[UUID, Parameter(title="Rule ID", description="The forwarding rule to update.")],
    ) -> ForwardingRule:
        """Update a forwarding rule."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        db_obj = await forwarding_rules_service.get_one(id=rule_id, extension_id=ext_id)
        before = capture_snapshot(db_obj)
        db_obj = await forwarding_rules_service.update(item_id=db_obj.id, data=data.to_dict())
        after = capture_snapshot(db_obj)
        await log_audit(
            audit_service,
            action="voice.forwarding_rule_update",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="forwarding_rule",
            target_id=db_obj.id,
            target_label=db_obj.destination_value,
            before=before,
            after=after,
            request=request,
        )
        return forwarding_rules_service.to_schema(db_obj, schema_type=ForwardingRule)

    @delete(
        operation_id="DeleteForwardingRule",
        path="/api/voice/extensions/{ext_id:uuid}/forwarding/{rule_id:uuid}",
        return_dto=None,
    )
    async def delete_forwarding_rule(
        self,
        request: Request[m.User, Token, Any],
        extensions_service: ExtensionService,
        forwarding_rules_service: ForwardingRuleService,
        audit_service: AuditLogService,
        current_user: m.User,
        ext_id: Annotated[UUID, Parameter(title="Extension ID", description="The extension.")],
        rule_id: Annotated[UUID, Parameter(title="Rule ID", description="The forwarding rule to delete.")],
    ) -> None:
        """Remove a forwarding rule."""
        await extensions_service.get_one(id=ext_id, user_id=current_user.id)
        db_obj = await forwarding_rules_service.get_one(id=rule_id, extension_id=ext_id)
        before = capture_snapshot(db_obj)
        target_label = db_obj.destination_value
        await forwarding_rules_service.delete(rule_id)
        await log_audit(
            audit_service,
            action="voice.forwarding_rule_delete",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_name=current_user.name,
            target_type="forwarding_rule",
            target_id=rule_id,
            target_label=target_label,
            before=before,
            after=None,
            request=request,
        )
