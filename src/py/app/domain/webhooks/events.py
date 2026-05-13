"""Webhook event type registry.

Defines all supported webhook event types and their descriptions.
Webhook endpoints subscribe to these event types to receive notifications.
"""

from __future__ import annotations

from enum import StrEnum


class WebhookEventType(StrEnum):
    """All supported webhook event types."""

    # User account events
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_ROLE_ASSIGNED = "user.role.assigned"
    USER_ROLE_REVOKED = "user.role.revoked"

    # Authentication events
    USER_MFA_CHALLENGE_SUCCESS = "user.mfa_challenge.success"
    USER_PASSWORD_RESET_REQUESTED = "user.password_reset.requested"
    USER_PASSWORD_RESET_COMPLETED = "user.password_reset.completed"
    USER_EMAIL_VERIFIED = "user.email.verified"
    USER_VERIFICATION_REQUESTED = "user.verification.requested"

    # Role events
    ROLE_CREATED = "role.created"
    ROLE_UPDATED = "role.updated"
    ROLE_DELETED = "role.deleted"

    # Team events
    TEAM_CREATED = "team.created"
    TEAM_UPDATED = "team.updated"
    TEAM_DELETED = "team.deleted"
    TEAM_MEMBER_INVITED = "team.member.invited"
    TEAM_INVITATION_CREATED = "team.invitation.created"
    TEAM_INVITATION_ACCEPTED = "team.invitation.accepted"
    TEAM_INVITATION_REJECTED = "team.invitation.rejected"
    TEAM_INVITATION_DELETED = "team.invitation.deleted"
    TEAM_MEMBER_ADDED = "team.member.added"
    TEAM_MEMBER_UPDATED = "team.member.updated"
    TEAM_MEMBER_REMOVED = "team.member.removed"
    TEAM_PERMISSIONS_UPDATED = "team.permissions.updated"

    # Organization events
    ORGANIZATION_CREATED = "organization.created"
    ORGANIZATION_UPDATED = "organization.updated"

    # Device events
    DEVICE_CREATED = "device.created"
    DEVICE_UPDATED = "device.updated"
    DEVICE_DELETED = "device.deleted"
    DEVICE_TEMPLATE_CREATED = "device.template.created"
    DEVICE_TEMPLATE_UPDATED = "device.template.updated"
    DEVICE_TEMPLATE_DELETED = "device.template.deleted"

    # Connection events
    CONNECTION_CREATED = "connection.created"
    CONNECTION_UPDATED = "connection.updated"
    CONNECTION_DELETED = "connection.deleted"

    # Location events
    LOCATION_CREATED = "location.created"
    LOCATION_UPDATED = "location.updated"
    LOCATION_DELETED = "location.deleted"

    # Schedule events
    SCHEDULE_CREATED = "schedule.created"
    SCHEDULE_UPDATED = "schedule.updated"
    SCHEDULE_DELETED = "schedule.deleted"
    SCHEDULE_ENTRY_CREATED = "schedule.entry.created"
    SCHEDULE_ENTRY_UPDATED = "schedule.entry.updated"
    SCHEDULE_ENTRY_DELETED = "schedule.entry.deleted"

    # E911 events
    E911_REGISTRATION_CREATED = "e911.registration.created"
    E911_REGISTRATION_UPDATED = "e911.registration.updated"
    E911_REGISTRATION_DELETED = "e911.registration.deleted"

    # Webhook events
    WEBHOOK_CREATED = "webhook.created"
    WEBHOOK_UPDATED = "webhook.updated"
    WEBHOOK_DELETED = "webhook.deleted"
    WEBHOOK_ENDPOINT_CREATED = "webhook.endpoint.created"
    WEBHOOK_ENDPOINT_UPDATED = "webhook.endpoint.updated"
    WEBHOOK_ENDPOINT_DELETED = "webhook.endpoint.deleted"

    # Call routing — call queue events
    CALL_QUEUE_CREATED = "call_queue.created"
    CALL_QUEUE_UPDATED = "call_queue.updated"
    CALL_QUEUE_DELETED = "call_queue.deleted"
    CALL_QUEUE_MEMBER_CREATED = "call_queue.member.created"
    CALL_QUEUE_MEMBER_UPDATED = "call_queue.member.updated"
    CALL_QUEUE_MEMBER_DELETED = "call_queue.member.deleted"

    # Call routing — IVR menu events
    IVR_MENU_CREATED = "ivr_menu.created"
    IVR_MENU_UPDATED = "ivr_menu.updated"
    IVR_MENU_DELETED = "ivr_menu.deleted"
    IVR_MENU_OPTION_CREATED = "ivr_menu.option.created"
    IVR_MENU_OPTION_UPDATED = "ivr_menu.option.updated"
    IVR_MENU_OPTION_DELETED = "ivr_menu.option.deleted"

    # Call routing — ring group events
    RING_GROUP_CREATED = "ring_group.created"
    RING_GROUP_UPDATED = "ring_group.updated"
    RING_GROUP_DELETED = "ring_group.deleted"
    RING_GROUP_MEMBER_CREATED = "ring_group.member.created"
    RING_GROUP_MEMBER_UPDATED = "ring_group.member.updated"
    RING_GROUP_MEMBER_DELETED = "ring_group.member.deleted"

    # Call routing — time condition events
    TIME_CONDITION_CREATED = "time_condition.created"
    TIME_CONDITION_UPDATED = "time_condition.updated"
    TIME_CONDITION_DELETED = "time_condition.deleted"

    # Voice — extension events
    EXTENSION_CREATED = "extension.created"
    EXTENSION_UPDATED = "extension.updated"
    EXTENSION_DELETED = "extension.deleted"

    # Voice — phone number events
    PHONE_NUMBER_CREATED = "phone_number.created"
    PHONE_NUMBER_UPDATED = "phone_number.updated"
    PHONE_NUMBER_DELETED = "phone_number.deleted"

    # Voice — forwarding events
    FORWARDING_CREATED = "forwarding.created"
    FORWARDING_UPDATED = "forwarding.updated"
    FORWARDING_DELETED = "forwarding.deleted"
    FORWARDING_BULK_REPLACED = "forwarding.bulk_replaced"

    # Voice — DND events
    DND_TOGGLED = "dnd.toggled"
    DND_UPDATED = "dnd.updated"

    # Voicemail events
    VOICEMAIL_BOX_CREATED = "voicemail_box.created"
    VOICEMAIL_BOX_UPDATED = "voicemail_box.updated"
    VOICEMAIL_BOX_DELETED = "voicemail_box.deleted"
    VOICEMAIL_MESSAGE_DELETED = "voicemail.message.deleted"
    VOICEMAIL_MESSAGE_UPDATED = "voicemail.message.updated"

    # Fax — fax number events
    FAX_NUMBER_CREATED = "fax_number.created"
    FAX_NUMBER_UPDATED = "fax_number.updated"
    FAX_NUMBER_DELETED = "fax_number.deleted"

    # Fax — email route events
    FAX_EMAIL_ROUTE_CREATED = "fax.email_route.created"
    FAX_EMAIL_ROUTE_UPDATED = "fax.email_route.updated"
    FAX_EMAIL_ROUTE_DELETED = "fax.email_route.deleted"

    # Fax — message events
    FAX_MESSAGE_CREATED = "fax.message.created"
    FAX_MESSAGE_DELETED = "fax.message.deleted"

    # Support — ticket events
    TICKET_CREATED = "ticket.created"
    TICKET_DELETED = "ticket.deleted"
    TICKET_STATUS_CHANGED = "ticket.status.changed"
    TICKET_ASSIGNED = "ticket.assigned"
    TICKET_MESSAGE_CREATED = "ticket.message.created"
    TICKET_MESSAGE_DELETED = "ticket.message.deleted"
    TICKET_MESSAGE_UPDATED = "ticket.message.updated"
    TICKET_ATTACHMENT_DELETED = "ticket.attachment.deleted"

    # Feedback events
    FEEDBACK_SUBMITTED = "feedback.submitted"

    # Tag events
    TAG_CREATED = "tag.created"
    TAG_UPDATED = "tag.updated"
    TAG_DELETED = "tag.deleted"

    # Notification events
    NOTIFICATION_DELETED = "notification.deleted"
    NOTIFICATIONS_BULK_DELETED = "notifications.bulk_deleted"

    # Analytics events
    CALL_RECORD_CREATED = "call_record.created"

    # Admin — music on hold events
    MUSIC_ON_HOLD_CREATED = "music_on_hold.created"
    MUSIC_ON_HOLD_UPDATED = "music_on_hold.updated"
    MUSIC_ON_HOLD_DELETED = "music_on_hold.deleted"

    # Admin — bulk import events
    DEVICES_BULK_IMPORTED = "admin.devices.bulk_imported"
    EXTENSIONS_BULK_IMPORTED = "admin.extensions.bulk_imported"

    # Admin — gateway events
    GATEWAY_SETTINGS_UPDATED = "admin.gateway.settings_updated"

    # Admin — user/team events (admin-specific)
    ADMIN_USER_UPDATED = "admin.user.updated"
    ADMIN_USER_DELETED = "admin.user.deleted"
    ADMIN_TEAM_UPDATED = "admin.team.updated"
    ADMIN_TEAM_DELETED = "admin.team.deleted"

    # Phone number bulk import events
    PHONE_NUMBERS_BULK_IMPORTED = "admin.phone_numbers.bulk_imported"

    # Device action events
    DEVICE_REBOOTED = "device.rebooted"
    DEVICE_REPROVISIONED = "device.reprovisioned"
    DEVICE_LINES_UPDATED = "device.lines.updated"

    # Notification preference events
    NOTIFICATION_PREFERENCES_UPDATED = "notification.preferences.updated"

    # Background task events
    BACKGROUND_TASK_CANCELLED = "background_task.cancelled"
    BACKGROUND_TASK_DELETED = "background_task.deleted"

    # Account security events
    MFA_DISABLED = "user.mfa.disabled"
    OAUTH_ACCOUNT_UNLINKED = "user.oauth.unlinked"
    SESSION_REVOKED = "user.session.revoked"
    SESSIONS_REVOKED_ALL = "user.sessions.revoked_all"


# Human-readable descriptions for each event type, useful for UI display
EVENT_DESCRIPTIONS: dict[WebhookEventType, str] = {
    # User account events
    WebhookEventType.USER_LOGIN: "A user successfully logged in",
    WebhookEventType.USER_LOGOUT: "A user logged out",
    WebhookEventType.USER_CREATED: "A new user account was created",
    WebhookEventType.USER_UPDATED: "A user account was updated",
    WebhookEventType.USER_DELETED: "A user account was deleted",
    WebhookEventType.USER_ROLE_ASSIGNED: "A role was assigned to a user",
    WebhookEventType.USER_ROLE_REVOKED: "A role was revoked from a user",
    # Authentication events
    WebhookEventType.USER_MFA_CHALLENGE_SUCCESS: "A user passed MFA verification",
    WebhookEventType.USER_PASSWORD_RESET_REQUESTED: "A password reset was requested",
    WebhookEventType.USER_PASSWORD_RESET_COMPLETED: "A password reset was completed",
    WebhookEventType.USER_EMAIL_VERIFIED: "A user's email was verified",
    WebhookEventType.USER_VERIFICATION_REQUESTED: "An email verification was requested",
    # Role events
    WebhookEventType.ROLE_CREATED: "A new role was created",
    WebhookEventType.ROLE_UPDATED: "A role was updated",
    WebhookEventType.ROLE_DELETED: "A role was deleted",
    # Team events
    WebhookEventType.TEAM_CREATED: "A new team was created",
    WebhookEventType.TEAM_UPDATED: "A team was updated",
    WebhookEventType.TEAM_DELETED: "A team was deleted",
    WebhookEventType.TEAM_MEMBER_INVITED: "A new member was invited to a team",
    WebhookEventType.TEAM_INVITATION_CREATED: "A team invitation was created",
    WebhookEventType.TEAM_INVITATION_ACCEPTED: "A team invitation was accepted",
    WebhookEventType.TEAM_INVITATION_REJECTED: "A team invitation was declined",
    WebhookEventType.TEAM_INVITATION_DELETED: "A team invitation was deleted",
    WebhookEventType.TEAM_MEMBER_ADDED: "A member was added to a team",
    WebhookEventType.TEAM_MEMBER_UPDATED: "A team member's role was updated",
    WebhookEventType.TEAM_MEMBER_REMOVED: "A member was removed from a team",
    WebhookEventType.TEAM_PERMISSIONS_UPDATED: "Team permissions were updated",
    # Organization events
    WebhookEventType.ORGANIZATION_CREATED: "An organization was created",
    WebhookEventType.ORGANIZATION_UPDATED: "An organization was updated",
    # Device events
    WebhookEventType.DEVICE_CREATED: "A new device was provisioned",
    WebhookEventType.DEVICE_UPDATED: "A device was updated",
    WebhookEventType.DEVICE_DELETED: "A device was deleted",
    WebhookEventType.DEVICE_TEMPLATE_CREATED: "A new device template was created",
    WebhookEventType.DEVICE_TEMPLATE_UPDATED: "A device template was updated",
    WebhookEventType.DEVICE_TEMPLATE_DELETED: "A device template was deleted",
    # Connection events
    WebhookEventType.CONNECTION_CREATED: "A new connection was created",
    WebhookEventType.CONNECTION_UPDATED: "A connection was updated",
    WebhookEventType.CONNECTION_DELETED: "A connection was deleted",
    # Location events
    WebhookEventType.LOCATION_CREATED: "A new location was created",
    WebhookEventType.LOCATION_UPDATED: "A location was updated",
    WebhookEventType.LOCATION_DELETED: "A location was deleted",
    # Schedule events
    WebhookEventType.SCHEDULE_CREATED: "A new schedule was created",
    WebhookEventType.SCHEDULE_UPDATED: "A schedule was updated",
    WebhookEventType.SCHEDULE_DELETED: "A schedule was deleted",
    WebhookEventType.SCHEDULE_ENTRY_CREATED: "A new schedule entry was created",
    WebhookEventType.SCHEDULE_ENTRY_UPDATED: "A schedule entry was updated",
    WebhookEventType.SCHEDULE_ENTRY_DELETED: "A schedule entry was deleted",
    # E911 events
    WebhookEventType.E911_REGISTRATION_CREATED: "A new E911 registration was created",
    WebhookEventType.E911_REGISTRATION_UPDATED: "An E911 registration was updated",
    WebhookEventType.E911_REGISTRATION_DELETED: "An E911 registration was deleted",
    # Webhook events
    WebhookEventType.WEBHOOK_CREATED: "A new webhook was created",
    WebhookEventType.WEBHOOK_UPDATED: "A webhook was updated",
    WebhookEventType.WEBHOOK_DELETED: "A webhook was deleted",
    WebhookEventType.WEBHOOK_ENDPOINT_CREATED: "A new webhook endpoint was created",
    WebhookEventType.WEBHOOK_ENDPOINT_UPDATED: "A webhook endpoint was updated",
    WebhookEventType.WEBHOOK_ENDPOINT_DELETED: "A webhook endpoint was deleted",
    # Call routing — call queue events
    WebhookEventType.CALL_QUEUE_CREATED: "A new call queue was created",
    WebhookEventType.CALL_QUEUE_UPDATED: "A call queue was updated",
    WebhookEventType.CALL_QUEUE_DELETED: "A call queue was deleted",
    WebhookEventType.CALL_QUEUE_MEMBER_CREATED: "A new member was added to a call queue",
    WebhookEventType.CALL_QUEUE_MEMBER_UPDATED: "A call queue member was updated",
    WebhookEventType.CALL_QUEUE_MEMBER_DELETED: "A call queue member was removed",
    # Call routing — IVR menu events
    WebhookEventType.IVR_MENU_CREATED: "A new IVR menu was created",
    WebhookEventType.IVR_MENU_UPDATED: "An IVR menu was updated",
    WebhookEventType.IVR_MENU_DELETED: "An IVR menu was deleted",
    WebhookEventType.IVR_MENU_OPTION_CREATED: "A new option was added to an IVR menu",
    WebhookEventType.IVR_MENU_OPTION_UPDATED: "An IVR menu option was updated",
    WebhookEventType.IVR_MENU_OPTION_DELETED: "An IVR menu option was deleted",
    # Call routing — ring group events
    WebhookEventType.RING_GROUP_CREATED: "A new ring group was created",
    WebhookEventType.RING_GROUP_UPDATED: "A ring group was updated",
    WebhookEventType.RING_GROUP_DELETED: "A ring group was deleted",
    WebhookEventType.RING_GROUP_MEMBER_CREATED: "A new member was added to a ring group",
    WebhookEventType.RING_GROUP_MEMBER_UPDATED: "A ring group member was updated",
    WebhookEventType.RING_GROUP_MEMBER_DELETED: "A ring group member was removed",
    # Call routing — time condition events
    WebhookEventType.TIME_CONDITION_CREATED: "A new time condition was created",
    WebhookEventType.TIME_CONDITION_UPDATED: "A time condition was updated",
    WebhookEventType.TIME_CONDITION_DELETED: "A time condition was deleted",
    # Voice — extension events
    WebhookEventType.EXTENSION_CREATED: "A new extension was created",
    WebhookEventType.EXTENSION_UPDATED: "An extension was updated",
    WebhookEventType.EXTENSION_DELETED: "An extension was deleted",
    # Voice — phone number events
    WebhookEventType.PHONE_NUMBER_CREATED: "A new phone number was created",
    WebhookEventType.PHONE_NUMBER_UPDATED: "A phone number was updated",
    WebhookEventType.PHONE_NUMBER_DELETED: "A phone number was deleted",
    # Voice — forwarding events
    WebhookEventType.FORWARDING_CREATED: "A new call forwarding rule was created",
    WebhookEventType.FORWARDING_UPDATED: "A call forwarding rule was updated",
    WebhookEventType.FORWARDING_DELETED: "A call forwarding rule was deleted",
    WebhookEventType.FORWARDING_BULK_REPLACED: "Call forwarding rules were bulk-replaced",
    # Voice — DND events
    WebhookEventType.DND_TOGGLED: "Do Not Disturb was toggled",
    WebhookEventType.DND_UPDATED: "Do Not Disturb settings were updated",
    # Voicemail events
    WebhookEventType.VOICEMAIL_BOX_CREATED: "A new voicemail box was created",
    WebhookEventType.VOICEMAIL_BOX_UPDATED: "A voicemail box was updated",
    WebhookEventType.VOICEMAIL_BOX_DELETED: "A voicemail box was deleted",
    WebhookEventType.VOICEMAIL_MESSAGE_DELETED: "A voicemail message was deleted",
    WebhookEventType.VOICEMAIL_MESSAGE_UPDATED: "A voicemail message was updated",
    # Fax — fax number events
    WebhookEventType.FAX_NUMBER_CREATED: "A new fax number was created",
    WebhookEventType.FAX_NUMBER_UPDATED: "A fax number was updated",
    WebhookEventType.FAX_NUMBER_DELETED: "A fax number was deleted",
    # Fax — email route events
    WebhookEventType.FAX_EMAIL_ROUTE_CREATED: "A new fax email route was created",
    WebhookEventType.FAX_EMAIL_ROUTE_UPDATED: "A fax email route was updated",
    WebhookEventType.FAX_EMAIL_ROUTE_DELETED: "A fax email route was deleted",
    # Fax — message events
    WebhookEventType.FAX_MESSAGE_CREATED: "A fax message was created or queued for send",
    WebhookEventType.FAX_MESSAGE_DELETED: "A fax message was deleted",
    # Support — ticket events
    WebhookEventType.TICKET_CREATED: "A new support ticket was created",
    WebhookEventType.TICKET_DELETED: "A support ticket was deleted",
    WebhookEventType.TICKET_STATUS_CHANGED: "A support ticket status was changed",
    WebhookEventType.TICKET_ASSIGNED: "A support ticket was assigned",
    WebhookEventType.TICKET_MESSAGE_CREATED: "A new message was added to a support ticket",
    WebhookEventType.TICKET_MESSAGE_DELETED: "A ticket message was deleted",
    WebhookEventType.TICKET_MESSAGE_UPDATED: "A ticket message was updated",
    WebhookEventType.TICKET_ATTACHMENT_DELETED: "A ticket attachment was deleted",
    # Feedback events
    WebhookEventType.FEEDBACK_SUBMITTED: "User feedback was submitted",
    # Tag events
    WebhookEventType.TAG_CREATED: "A new tag was created",
    WebhookEventType.TAG_UPDATED: "A tag was updated",
    WebhookEventType.TAG_DELETED: "A tag was deleted",
    # Notification events
    WebhookEventType.NOTIFICATION_DELETED: "A notification was deleted",
    WebhookEventType.NOTIFICATIONS_BULK_DELETED: "Multiple notifications were deleted",
    # Analytics events
    WebhookEventType.CALL_RECORD_CREATED: "A new call record was created",
    # Admin — music on hold events
    WebhookEventType.MUSIC_ON_HOLD_CREATED: "A new music on hold entry was created",
    WebhookEventType.MUSIC_ON_HOLD_UPDATED: "A music on hold entry was updated",
    WebhookEventType.MUSIC_ON_HOLD_DELETED: "A music on hold entry was deleted",
    # Background task events
    WebhookEventType.DEVICES_BULK_IMPORTED: "Devices were bulk-imported from CSV",
    WebhookEventType.EXTENSIONS_BULK_IMPORTED: "Extensions were bulk-imported from CSV",
    WebhookEventType.GATEWAY_SETTINGS_UPDATED: "Gateway settings were updated",
    WebhookEventType.ADMIN_USER_UPDATED: "A user was updated via admin panel",
    WebhookEventType.ADMIN_USER_DELETED: "A user was deleted via admin panel",
    WebhookEventType.ADMIN_TEAM_UPDATED: "A team was updated via admin panel",
    WebhookEventType.ADMIN_TEAM_DELETED: "A team was deleted via admin panel",
    WebhookEventType.PHONE_NUMBERS_BULK_IMPORTED: "Phone numbers were bulk-imported",
    WebhookEventType.DEVICE_REBOOTED: "A device reboot was initiated",
    WebhookEventType.DEVICE_REPROVISIONED: "A device reprovision was initiated",
    WebhookEventType.DEVICE_LINES_UPDATED: "Device line assignments were updated",
    WebhookEventType.NOTIFICATION_PREFERENCES_UPDATED: "Notification preferences were updated",
    WebhookEventType.BACKGROUND_TASK_CANCELLED: "A background task was cancelled",
    WebhookEventType.BACKGROUND_TASK_DELETED: "A background task was deleted",
    # Account security events
    WebhookEventType.MFA_DISABLED: "MFA was disabled for a user account",
    WebhookEventType.OAUTH_ACCOUNT_UNLINKED: "An OAuth provider was unlinked from a user account",
    WebhookEventType.SESSION_REVOKED: "A user session was revoked",
    WebhookEventType.SESSIONS_REVOKED_ALL: "All other user sessions were revoked",
}


def get_all_event_types() -> list[dict[str, str]]:
    """Return all event types with descriptions for API consumers.

    Returns:
        List of dicts with 'event' and 'description' keys.
    """
    return [{"event": evt.value, "description": EVENT_DESCRIPTIONS.get(evt, "")} for evt in WebhookEventType]
