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

    # Authentication events
    USER_MFA_CHALLENGE_SUCCESS = "user.mfa_challenge.success"
    USER_PASSWORD_RESET_REQUESTED = "user.password_reset.requested"
    USER_PASSWORD_RESET_COMPLETED = "user.password_reset.completed"
    USER_EMAIL_VERIFIED = "user.email.verified"

    # Team events
    TEAM_CREATED = "team.created"
    TEAM_MEMBER_INVITED = "team.member.invited"


# Human-readable descriptions for each event type, useful for UI display
EVENT_DESCRIPTIONS: dict[WebhookEventType, str] = {
    WebhookEventType.USER_LOGIN: "A user successfully logged in",
    WebhookEventType.USER_LOGOUT: "A user logged out",
    WebhookEventType.USER_CREATED: "A new user account was created",
    WebhookEventType.USER_UPDATED: "A user account was updated",
    WebhookEventType.USER_DELETED: "A user account was deleted",
    WebhookEventType.USER_MFA_CHALLENGE_SUCCESS: "A user passed MFA verification",
    WebhookEventType.USER_PASSWORD_RESET_REQUESTED: "A password reset was requested",
    WebhookEventType.USER_PASSWORD_RESET_COMPLETED: "A password reset was completed",
    WebhookEventType.USER_EMAIL_VERIFIED: "A user's email was verified",
    WebhookEventType.TEAM_CREATED: "A new team was created",
    WebhookEventType.TEAM_MEMBER_INVITED: "A new member was invited to a team",
}


def get_all_event_types() -> list[dict[str, str]]:
    """Return all event types with descriptions for API consumers.

    Returns:
        List of dicts with 'event' and 'description' keys.
    """
    return [
        {"event": evt.value, "description": EVENT_DESCRIPTIONS.get(evt, "")}
        for evt in WebhookEventType
    ]
