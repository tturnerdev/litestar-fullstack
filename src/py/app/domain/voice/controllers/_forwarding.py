"""Forwarding Rule Controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

from litestar import Controller, delete, get, patch, post, put
from litestar.di import Provide
from litestar.params import Dependency, Parameter
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT

from app.db import models as m
from app.domain.admin.deps import provide_audit_log_service
from app.domain.teams.guards import requires_feature_permission
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

    tags = ["Voice Forwarding"]
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
                "search": "destination_value",
            },
        ),
    }

    @get(
        operation_id="ListForwardingRules",
        summary="List forwarding rules",
        description="Retrieve a paginated list of forwarding rules for an extension, sorted by priority. Supports search by destination value. The caller must own the extension.",
        path="/api/voice/extensions/{ext_id:uuid}/forwarding",
        guards=[requires_feature_permission("voice", "view"), requires_extension_ownership],
    )
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

    @post(
        operation_id="CreateForwardingRule",
        summary="Create a forwarding rule",
        description="Add a new forwarding rule to an extension. Logs an audit entry and emits forwarding-changed and creation events. The caller must own the extension.",
        path="/api/voice/extensions/{ext_id:uuid}/forwarding",
        guards=[requires_feature_permission("voice", "edit"), requires_extension_ownership],
        status_code=HTTP_201_CREATED,
    )
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
        request.app.emit(event_id="forwarding_created", rule_id=db_obj.id)
        after = capture_snapshot(db_obj)
        result = forwarding_rules_service.to_schema(db_obj, schema_type=ForwardingRule)
        await log_audit(
            audit_service,
            action="voice.forwarding_rule.created",
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
        request.app.emit(event_id="forwarding_rules_changed", extension_id=ext_id)
        return result

    @put(
        operation_id="SetForwardingRules",
        summary="Replace all forwarding rules",
        description="Bulk-replace all forwarding rules for an extension. Deletes existing rules and creates new ones from the request body. Logs a before/after audit entry. The caller must own the extension.",
        path="/api/voice/extensions/{ext_id:uuid}/forwarding",
        guards=[requires_feature_permission("voice", "edit"), requires_extension_ownership],
    )
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
            action="voice.forwarding_rule.bulk_replaced",
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
        request.app.emit(event_id="forwarding_bulk_replaced", extension_id=ext_id)
        request.app.emit(event_id="forwarding_rules_changed", extension_id=ext_id)
        return results

    @patch(
        operation_id="UpdateForwardingRule",
        summary="Update a forwarding rule",
        description="Update fields on a single forwarding rule. Logs an audit entry and emits a forwarding-changed event. The caller must own the parent extension.",
        path="/api/voice/extensions/{ext_id:uuid}/forwarding/{rule_id:uuid}",
        guards=[requires_feature_permission("voice", "edit"), requires_extension_ownership],
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
        request.app.emit(event_id="forwarding_updated", rule_id=db_obj.id)
        after = capture_snapshot(db_obj)
        result = forwarding_rules_service.to_schema(db_obj, schema_type=ForwardingRule)
        await log_audit(
            audit_service,
            action="voice.forwarding_rule.updated",
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
        request.app.emit(event_id="forwarding_rules_changed", extension_id=ext_id)
        return result

    @delete(
        operation_id="DeleteForwardingRule",
        summary="Delete a forwarding rule",
        description="Remove a single forwarding rule from an extension. Logs an audit entry and emits a forwarding-changed event. The caller must own the parent extension.",
        path="/api/voice/extensions/{ext_id:uuid}/forwarding/{rule_id:uuid}",
        return_dto=None,
        guards=[requires_feature_permission("voice", "edit"), requires_extension_ownership],
        status_code=HTTP_204_NO_CONTENT,
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
        request.app.emit(event_id="forwarding_deleted", rule_id=rule_id)
        await forwarding_rules_service.delete(rule_id)
        await log_audit(
            audit_service,
            action="voice.forwarding_rule.deleted",
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
        request.app.emit(event_id="forwarding_rules_changed", extension_id=ext_id)
