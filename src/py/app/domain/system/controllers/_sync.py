"""Generic entity sync controller."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

import structlog
from litestar import Controller, get
from litestar.exceptions import NotFoundException, ValidationException

from app.domain.system.schemas._sync import SyncResponse

if TYPE_CHECKING:
    from advanced_alchemy.extensions.litestar import service
    from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger()


@dataclass(frozen=True)
class _DomainRegistration:
    """Registry entry mapping a domain path to its model, service, and allowed lookup fields."""

    model_path: str
    """Dotted import path to the model class (e.g. 'app.db.models.Team')."""
    service_path: str
    """Dotted import path to the service class (e.g. 'app.domain.teams.services.TeamService')."""
    allowed_fields: frozenset[str] = field(default_factory=lambda: frozenset({"id"}))
    """Set of field names allowed for lookup."""


# ---------------------------------------------------------------------------
# Domain registry
#
# Each entry maps a URL path segment to the model, service, and fields that
# are valid for lookup.  New domains only need an entry here to become
# syncable.  Service and model classes are imported lazily so domains that
# have not been created yet won't cause import errors at startup.
# ---------------------------------------------------------------------------
_DOMAIN_REGISTRY: dict[str, _DomainRegistration] = {
    "teams": _DomainRegistration(
        model_path="app.db.models.Team",
        service_path="app.domain.teams.services.TeamService",
        allowed_fields=frozenset({"id", "name", "slug"}),
    ),
    "devices": _DomainRegistration(
        model_path="app.db.models.Device",
        service_path="app.domain.devices.services.DeviceService",
        allowed_fields=frozenset({"id", "name", "mac_address", "serial_number"}),
    ),
    "voice/extensions": _DomainRegistration(
        model_path="app.db.models.Extension",
        service_path="app.domain.voice.services.ExtensionService",
        allowed_fields=frozenset({"id", "extension_number"}),
    ),
    "voice/numbers": _DomainRegistration(
        model_path="app.db.models.PhoneNumber",
        service_path="app.domain.voice.services.PhoneNumberService",
        allowed_fields=frozenset({"id", "number"}),
    ),
    "fax/numbers": _DomainRegistration(
        model_path="app.db.models.FaxNumber",
        service_path="app.domain.fax.services.FaxNumberService",
        allowed_fields=frozenset({"id", "number"}),
    ),
    "support/tickets": _DomainRegistration(
        model_path="app.db.models.Ticket",
        service_path="app.domain.support.services.TicketService",
        allowed_fields=frozenset({"id", "ticket_number"}),
    ),
    "locations": _DomainRegistration(
        model_path="app.db.models.Location",
        service_path="app.domain.locations.services.LocationService",
        allowed_fields=frozenset({"id", "name"}),
    ),
    "connections": _DomainRegistration(
        model_path="app.db.models.Connection",
        service_path="app.domain.connections.services.ConnectionService",
        allowed_fields=frozenset({"id", "name"}),
    ),
}


def _import_class(dotted_path: str) -> type:
    """Import a class from a dotted path like 'app.db.models.Team'.

    Args:
        dotted_path: Fully-qualified dotted import path.

    Returns:
        The imported class.
    """
    import importlib

    module_path, _, class_name = dotted_path.rpartition(".")
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


def _model_to_dict(instance: Any) -> dict[str, Any]:
    """Convert a SQLAlchemy model instance to a JSON-safe dictionary.

    Handles UUIDs, datetimes, and other non-JSON-native types.

    Args:
        instance: The SQLAlchemy model instance.

    Returns:
        A dictionary representation of the model.
    """
    from sqlalchemy import inspect as sa_inspect

    mapper = sa_inspect(type(instance))
    result: dict[str, Any] = {}
    for col in mapper.columns:
        value = getattr(instance, col.key, None)
        if isinstance(value, UUID):
            value = str(value)
        elif isinstance(value, datetime):
            value = value.isoformat()
        result[col.key] = value
    return result


class SyncController(Controller):
    """Generic entity sync endpoint.

    Allows looking up and syncing entities across any registered domain
    by an arbitrary lookup field.
    """

    tags = ["System"]

    @get(
        operation_id="SyncEntity",
        name="system:sync-entity",
        path="/api/sync/{domain:path}/{field_name:str}/{value:str}",
        summary="Sync Entity",
    )
    async def sync_entity(
        self,
        db_session: AsyncSession,
        domain: str,
        field_name: str,
        value: str,
    ) -> SyncResponse:
        """Look up and sync an entity by domain, field, and value.

        The value parameter is automatically URL-decoded by Litestar,
        so encoded characters (spaces, colons for MAC addresses, etc.)
        are handled transparently.

        Args:
            db_session: The database session.
            domain: The domain path (e.g. 'teams', 'voice/extensions').
            field_name: The model field to search by (e.g. 'id', 'name').
            value: The value to match against.

        Returns:
            SyncResponse with the entity data.

        Raises:
            NotFoundException: If the domain is not registered or the entity is not found.
            ValidationException: If the field is not allowed for lookup.
        """
        registration = _DOMAIN_REGISTRY.get(domain)
        if registration is None:
            msg = f"Unknown sync domain: {domain}"
            raise NotFoundException(detail=msg)

        if field_name not in registration.allowed_fields:
            allowed = ", ".join(sorted(registration.allowed_fields))
            msg = f"Field '{field_name}' is not allowed for domain '{domain}'. Allowed fields: {allowed}"
            raise ValidationException(detail=msg)

        # Lazily import the service class.
        try:
            service_cls: type[service.SQLAlchemyAsyncRepositoryService[Any]] = _import_class(
                registration.service_path,
            )
        except (ImportError, AttributeError) as exc:
            await logger.awarning("Sync domain not available", domain=domain, error=str(exc))
            msg = f"Domain '{domain}' is not available"
            raise NotFoundException(detail=msg) from exc

        svc = service_cls(session=db_session)

        # Coerce value for UUID fields.
        lookup_value: Any = value
        if field_name == "id":
            try:
                lookup_value = UUID(value)
            except ValueError as exc:
                msg = f"Invalid UUID: {value}"
                raise ValidationException(detail=msg) from exc

        entity = await svc.get_one_or_none(**{field_name: lookup_value})
        if entity is None:
            msg = f"Entity not found in '{domain}' where {field_name}={value}"
            raise NotFoundException(detail=msg)

        await logger.ainfo("Entity synced", domain=domain, field=field_name, value=value)

        return SyncResponse(
            synced=True,
            domain=domain,
            field=field_name,
            value=value,
            entity=_model_to_dict(entity),
            synced_at=datetime.now(UTC),
        )
