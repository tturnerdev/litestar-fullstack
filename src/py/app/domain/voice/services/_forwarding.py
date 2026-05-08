from __future__ import annotations

from typing import TYPE_CHECKING, Any

from advanced_alchemy.extensions.litestar import repository, service
from litestar.exceptions import ValidationException

from app.db import models as m

if TYPE_CHECKING:
    from advanced_alchemy.service import ModelDictT


class ForwardingRuleService(service.SQLAlchemyAsyncRepositoryService[m.ForwardingRule]):
    """Forwarding Rule Service."""

    class Repo(repository.SQLAlchemyAsyncRepository[m.ForwardingRule]):
        """Forwarding Rule Repository."""

        model_type = m.ForwardingRule

    repository_type = Repo
    match_fields = ["extension_id", "rule_type"]

    async def to_model_on_create(self, data: ModelDictT[m.ForwardingRule]) -> ModelDictT[m.ForwardingRule]:
        data = service.schema_dump(data)
        if service.is_dict(data):
            existing = await self.repository.list(
                m.ForwardingRule.extension_id == data["extension_id"],
                m.ForwardingRule.rule_type == data["rule_type"],
            )
            if existing:
                raise ValidationException("A forwarding rule of this type already exists for this extension.")
        return data

    async def to_model_on_update(self, data: ModelDictT[m.ForwardingRule], item_id: Any | None = None, **kwargs: Any) -> ModelDictT[m.ForwardingRule]:
        data = service.schema_dump(data)
        if service.is_dict(data) and "rule_type" in data:
            extension_id = data.get("extension_id")
            if extension_id:
                existing = await self.repository.list(
                    m.ForwardingRule.extension_id == extension_id,
                    m.ForwardingRule.rule_type == data["rule_type"],
                )
                if existing and any(str(e.id) != str(item_id) for e in existing):
                    raise ValidationException("A forwarding rule of this type already exists for this extension.")
        return data
