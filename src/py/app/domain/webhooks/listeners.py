"""Webhook domain event listeners.

Bridges internal app.emit() events to the webhook delivery system by
mapping each internal event ID (snake_case) to its WebhookEventType value
(dot.notation) and dispatching to all subscribed webhook endpoints.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import structlog
from litestar.events import listener

from app.domain.webhooks import deps
from app.domain.webhooks.events import WebhookEventType
from app.domain.webhooks.services._webhook_dispatcher import dispatch_webhook_event
from app.lib.deps import provide_services

logger = structlog.get_logger()

# Maps internal event IDs (as passed to request.app.emit(event_id=...))
# to their corresponding WebhookEventType values.
EVENT_MAP: dict[str, WebhookEventType] = {
    # User account events
    "user_created": WebhookEventType.USER_CREATED,
    "user_updated": WebhookEventType.USER_UPDATED,
    "user_deleted": WebhookEventType.USER_DELETED,
    "user_role_assigned": WebhookEventType.USER_ROLE_ASSIGNED,
    "user_role_revoked": WebhookEventType.USER_ROLE_REVOKED,
    # Authentication events
    "verification_requested": WebhookEventType.USER_VERIFICATION_REQUESTED,
    "password_reset_requested": WebhookEventType.USER_PASSWORD_RESET_REQUESTED,
    "password_reset_completed": WebhookEventType.USER_PASSWORD_RESET_COMPLETED,
    # Role events
    "role_created": WebhookEventType.ROLE_CREATED,
    "role_updated": WebhookEventType.ROLE_UPDATED,
    "role_deleted": WebhookEventType.ROLE_DELETED,
    # Team events
    "team_created": WebhookEventType.TEAM_CREATED,
    "team_updated": WebhookEventType.TEAM_UPDATED,
    "team_deleted": WebhookEventType.TEAM_DELETED,
    "team_invitation_created": WebhookEventType.TEAM_INVITATION_CREATED,
    "team_invitation_deleted": WebhookEventType.TEAM_INVITATION_DELETED,
    "team_member_removed": WebhookEventType.TEAM_MEMBER_REMOVED,
    "team_permissions_updated": WebhookEventType.TEAM_PERMISSIONS_UPDATED,
    # Organization events
    "organization_created": WebhookEventType.ORGANIZATION_CREATED,
    "organization_updated": WebhookEventType.ORGANIZATION_UPDATED,
    # Device events
    "device_created": WebhookEventType.DEVICE_CREATED,
    "device_updated": WebhookEventType.DEVICE_UPDATED,
    "device_deleted": WebhookEventType.DEVICE_DELETED,
    "device_template_created": WebhookEventType.DEVICE_TEMPLATE_CREATED,
    "device_template_deleted": WebhookEventType.DEVICE_TEMPLATE_DELETED,
    # Connection events
    "connection_created": WebhookEventType.CONNECTION_CREATED,
    "connection_updated": WebhookEventType.CONNECTION_UPDATED,
    "connection_deleted": WebhookEventType.CONNECTION_DELETED,
    # Location events
    "location_created": WebhookEventType.LOCATION_CREATED,
    "location_updated": WebhookEventType.LOCATION_UPDATED,
    "location_deleted": WebhookEventType.LOCATION_DELETED,
    # Schedule events
    "schedule_created": WebhookEventType.SCHEDULE_CREATED,
    "schedule_updated": WebhookEventType.SCHEDULE_UPDATED,
    "schedule_deleted": WebhookEventType.SCHEDULE_DELETED,
    "schedule_entry_created": WebhookEventType.SCHEDULE_ENTRY_CREATED,
    "schedule_entry_updated": WebhookEventType.SCHEDULE_ENTRY_UPDATED,
    "schedule_entry_deleted": WebhookEventType.SCHEDULE_ENTRY_DELETED,
    # E911 events
    "e911_registration_created": WebhookEventType.E911_REGISTRATION_CREATED,
    "e911_registration_updated": WebhookEventType.E911_REGISTRATION_UPDATED,
    "e911_registration_deleted": WebhookEventType.E911_REGISTRATION_DELETED,
    # Webhook events
    "webhook_created": WebhookEventType.WEBHOOK_CREATED,
    "webhook_updated": WebhookEventType.WEBHOOK_UPDATED,
    "webhook_deleted": WebhookEventType.WEBHOOK_DELETED,
    "webhook_endpoint_created": WebhookEventType.WEBHOOK_ENDPOINT_CREATED,
    "webhook_endpoint_updated": WebhookEventType.WEBHOOK_ENDPOINT_UPDATED,
    "webhook_endpoint_deleted": WebhookEventType.WEBHOOK_ENDPOINT_DELETED,
    # Call routing — call queue events
    "call_queue_created": WebhookEventType.CALL_QUEUE_CREATED,
    "call_queue_updated": WebhookEventType.CALL_QUEUE_UPDATED,
    "call_queue_deleted": WebhookEventType.CALL_QUEUE_DELETED,
    "call_queue_member_updated": WebhookEventType.CALL_QUEUE_MEMBER_UPDATED,
    "call_queue_member_deleted": WebhookEventType.CALL_QUEUE_MEMBER_DELETED,
    # Call routing — IVR menu events
    "ivr_menu_created": WebhookEventType.IVR_MENU_CREATED,
    "ivr_menu_updated": WebhookEventType.IVR_MENU_UPDATED,
    "ivr_menu_deleted": WebhookEventType.IVR_MENU_DELETED,
    "ivr_menu_option_updated": WebhookEventType.IVR_MENU_OPTION_UPDATED,
    "ivr_menu_option_deleted": WebhookEventType.IVR_MENU_OPTION_DELETED,
    # Call routing — ring group events
    "ring_group_created": WebhookEventType.RING_GROUP_CREATED,
    "ring_group_updated": WebhookEventType.RING_GROUP_UPDATED,
    "ring_group_deleted": WebhookEventType.RING_GROUP_DELETED,
    "ring_group_member_updated": WebhookEventType.RING_GROUP_MEMBER_UPDATED,
    "ring_group_member_deleted": WebhookEventType.RING_GROUP_MEMBER_DELETED,
    # Call routing — time condition events
    "time_condition_created": WebhookEventType.TIME_CONDITION_CREATED,
    "time_condition_updated": WebhookEventType.TIME_CONDITION_UPDATED,
    "time_condition_deleted": WebhookEventType.TIME_CONDITION_DELETED,
    # Voice — extension events
    "extension_created": WebhookEventType.EXTENSION_CREATED,
    "extension_updated": WebhookEventType.EXTENSION_UPDATED,
    "extension_deleted": WebhookEventType.EXTENSION_DELETED,
    # Voice — phone number events
    "phone_number_created": WebhookEventType.PHONE_NUMBER_CREATED,
    "phone_number_updated": WebhookEventType.PHONE_NUMBER_UPDATED,
    "phone_number_deleted": WebhookEventType.PHONE_NUMBER_DELETED,
    # Voice — forwarding events
    "forwarding_created": WebhookEventType.FORWARDING_CREATED,
    "forwarding_updated": WebhookEventType.FORWARDING_UPDATED,
    "forwarding_deleted": WebhookEventType.FORWARDING_DELETED,
    # Voice — DND events
    "dnd_toggled": WebhookEventType.DND_TOGGLED,
    "dnd_updated": WebhookEventType.DND_UPDATED,
    # Voicemail events
    "voicemail_box_created": WebhookEventType.VOICEMAIL_BOX_CREATED,
    "voicemail_box_updated": WebhookEventType.VOICEMAIL_BOX_UPDATED,
    "voicemail_box_deleted": WebhookEventType.VOICEMAIL_BOX_DELETED,
    "voicemail_message_deleted": WebhookEventType.VOICEMAIL_MESSAGE_DELETED,
    "voicemail_message_updated": WebhookEventType.VOICEMAIL_MESSAGE_UPDATED,
    # Fax — fax number events
    "fax_number_created": WebhookEventType.FAX_NUMBER_CREATED,
    "fax_number_updated": WebhookEventType.FAX_NUMBER_UPDATED,
    "fax_number_deleted": WebhookEventType.FAX_NUMBER_DELETED,
    # Fax — email route events
    "fax_email_route_created": WebhookEventType.FAX_EMAIL_ROUTE_CREATED,
    "fax_email_route_updated": WebhookEventType.FAX_EMAIL_ROUTE_UPDATED,
    "fax_email_route_deleted": WebhookEventType.FAX_EMAIL_ROUTE_DELETED,
    # Fax — message events
    "fax_message_deleted": WebhookEventType.FAX_MESSAGE_DELETED,
    # Support — ticket events
    "ticket_created": WebhookEventType.TICKET_CREATED,
    "ticket_deleted": WebhookEventType.TICKET_DELETED,
    "ticket_status_changed": WebhookEventType.TICKET_STATUS_CHANGED,
    "ticket_assigned": WebhookEventType.TICKET_ASSIGNED,
    "ticket_message_created": WebhookEventType.TICKET_MESSAGE_CREATED,
    "ticket_message_deleted": WebhookEventType.TICKET_MESSAGE_DELETED,
    "ticket_message_updated": WebhookEventType.TICKET_MESSAGE_UPDATED,
    "ticket_attachment_deleted": WebhookEventType.TICKET_ATTACHMENT_DELETED,
    # Tag events
    "tag_created": WebhookEventType.TAG_CREATED,
    "tag_updated": WebhookEventType.TAG_UPDATED,
    "tag_deleted": WebhookEventType.TAG_DELETED,
    # Notification events
    "notification_deleted": WebhookEventType.NOTIFICATION_DELETED,
    "notifications_bulk_deleted": WebhookEventType.NOTIFICATIONS_BULK_DELETED,
    # Analytics events
    "call_record_created": WebhookEventType.CALL_RECORD_CREATED,
    # Admin — music on hold events
    "music_on_hold_created": WebhookEventType.MUSIC_ON_HOLD_CREATED,
    "music_on_hold_deleted": WebhookEventType.MUSIC_ON_HOLD_DELETED,
    # Admin bulk import events
    "devices_bulk_imported": WebhookEventType.DEVICES_BULK_IMPORTED,
    "extensions_bulk_imported": WebhookEventType.EXTENSIONS_BULK_IMPORTED,
    # Admin gateway events
    "gateway_settings_updated": WebhookEventType.GATEWAY_SETTINGS_UPDATED,
    # Admin user/team events
    "admin_user_updated": WebhookEventType.ADMIN_USER_UPDATED,
    "admin_user_deleted": WebhookEventType.ADMIN_USER_DELETED,
    "admin_team_updated": WebhookEventType.ADMIN_TEAM_UPDATED,
    "admin_team_deleted": WebhookEventType.ADMIN_TEAM_DELETED,
    # Phone number bulk import events
    "phone_numbers_bulk_imported": WebhookEventType.PHONE_NUMBERS_BULK_IMPORTED,
    # Device action events
    "device_rebooted": WebhookEventType.DEVICE_REBOOTED,
    "device_reprovisioned": WebhookEventType.DEVICE_REPROVISIONED,
    "device_lines_updated": WebhookEventType.DEVICE_LINES_UPDATED,
    # Notification preference events
    "notification_preferences_updated": WebhookEventType.NOTIFICATION_PREFERENCES_UPDATED,
    # Background task events
    "background_task_deleted": WebhookEventType.BACKGROUND_TASK_DELETED,
}


async def _dispatch_webhook(internal_event_id: str, **kwargs: Any) -> None:
    """Generic webhook dispatch handler.

    Looks up the internal event ID in EVENT_MAP, extracts the entity
    identifier from kwargs, and dispatches to all subscribed webhook
    endpoints.

    Args:
        internal_event_id: The internal event ID (e.g., "team_created").
        **kwargs: Event payload — typically includes entity_id or a
            domain-specific ID key (team_id, webhook_id, etc.).
    """
    webhook_event_type = EVENT_MAP.get(internal_event_id)
    if webhook_event_type is None:
        await logger.awarning(
            "No webhook event type mapping for internal event",
            internal_event_id=internal_event_id,
        )
        return

    # Extract the entity identifier from kwargs.  Controllers use different
    # kwarg names (entity_id, team_id, device_id, etc.).  Rather than
    # maintaining a hardcoded list, we pick the first UUID-valued key
    # ending in "_id" and normalise it into the payload as "entity_id".
    entity_id: UUID | None = None
    entity_id_key: str | None = None
    for key, value in kwargs.items():
        if isinstance(value, UUID) and key.endswith("_id"):
            entity_id = value
            entity_id_key = key
            break

    payload: dict[str, Any] = {}
    if entity_id is not None:
        payload["entity_id"] = str(entity_id)

    for key, value in kwargs.items():
        if key == entity_id_key or key == "mailer":
            continue
        payload[key] = str(value) if isinstance(value, UUID) else value

    async with provide_services(
        deps.provide_webhook_endpoint_service,
        deps.provide_webhook_delivery_service,
    ) as (endpoint_service, delivery_service):
        await dispatch_webhook_event(
            event_type=webhook_event_type.value,
            payload=payload,
            endpoint_service=endpoint_service,
            delivery_service=delivery_service,
        )


def _make_listener(internal_event_id: str) -> Any:
    """Create a listener-decorated handler for a specific internal event ID.

    Args:
        internal_event_id: The event ID to listen for.

    Returns:
        A decorated async listener function (EventListener instance).
    """

    @listener(internal_event_id)
    async def _handler(**kwargs: Any) -> None:
        await _dispatch_webhook(internal_event_id, **kwargs)

    return _handler


# Dynamically register a listener for every mapped event and expose them
# at module level so the auto-discovery system can find them via __all__
# + getattr(module, name).
__all__: tuple[str, ...] = tuple(f"webhook_dispatch_{event_id}" for event_id in EVENT_MAP)

for _event_id in EVENT_MAP:
    globals()[f"webhook_dispatch_{_event_id}"] = _make_listener(_event_id)
