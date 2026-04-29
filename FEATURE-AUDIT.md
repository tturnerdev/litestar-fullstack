# Feature: Comprehensive Audit Logging

## Overview

Implement full audit trail coverage across all portal domains, recording every create, update, and delete action with before/after change snapshots. The existing `AuditLog` model and `AuditLogService` provide the foundation but currently only a handful of admin operations write audit entries. This plan extends coverage to every domain action and enhances the data model to capture field-level change diffs.

## Current State

### What exists
- **Model**: `src/py/app/db/models/_audit_log.py` — `AuditLog` with fields: `actor_id`, `actor_email`, `action`, `target_type`, `target_id`, `target_label`, `details` (JSONB), `ip_address`, `user_agent`
- **Service**: `src/py/app/domain/admin/services/_audit.py` — `AuditLogService` with `log_action()` and convenience methods for admin user/team operations
- **Controller**: `src/py/app/domain/admin/controllers/_audit.py` — read-only endpoints for listing/filtering audit logs (superuser only)
- **Frontend**: `src/js/web/src/components/admin/audit-log-table.tsx` — table with filtering, pagination
- **Event system**: Litestar `@listener` decorators in each domain's `listeners.py`, auto-discovered by `DomainPlugin`

### What's missing
- Only `admin.user.update`, `admin.user.delete`, `admin.team.update`, `admin.team.delete` write audit entries
- No other domain (voice, fax, support, devices, locations, connections, teams, accounts) writes audit entries
- The `details` JSONB field exists but no standard schema for before/after values
- Only 5 controllers emit events via `request.app.emit()` (user_created, password_reset_requested/completed, verification_requested, team_invitation_created)
- Existing listeners only log to structlog, not to AuditLog
- Frontend shows a flat table with no detail/diff view

## Design

### 1. Enhanced AuditLog Details Schema

Use the existing `details` JSONB column with a standardized structure — no model migration needed:

```json
{
  "before": {
    "name": "Old Team Name",
    "is_active": true
  },
  "after": {
    "name": "New Team Name",
    "is_active": false
  },
  "changed_fields": ["name", "is_active"],
  "metadata": {}
}
```

**Action-specific conventions:**
- **Create**: `before` is `null`, `after` contains all initial field values
- **Update**: `before` contains previous values (only changed fields), `after` contains new values (only changed fields), `changed_fields` lists the field names
- **Delete**: `before` contains the entity's final state, `after` is `null`
- **Other actions** (login, logout, MFA events, etc.): `metadata` contains action-specific context

### 2. Audit Mixin for Services

Create a reusable mixin at `src/py/app/lib/audit.py` that any service can inherit to get automatic audit logging:

```python
class AuditMixin:
    """Mixin for services that need audit logging.

    Provides capture_snapshot() to serialize an entity's auditable fields,
    and log_audit() to write a structured audit entry.
    """

    audit_target_type: str  # e.g., "device", "phone_number"
    audit_label_field: str = "name"  # field used for target_label
    audit_exclude_fields: set[str] = {"id", "created_at", "updated_at", "sa_orm_sentinel"}

    def capture_snapshot(self, obj) -> dict:
        """Serialize an entity to a dict for before/after comparison."""
        ...

    def compute_diff(self, before: dict, after: dict) -> tuple[dict, dict, list[str]]:
        """Return (before_changes, after_changes, changed_fields) for only the fields that differ."""
        ...

    async def log_audit(
        self,
        action: str,
        actor: User,
        target: object,
        before: dict | None = None,
        after: dict | None = None,
        request: Request | None = None,
        metadata: dict | None = None,
    ) -> None:
        """Write a structured audit log entry."""
        ...
```

### 3. Action Naming Convention

Use dotted, lowercase action names: `{domain}.{entity}.{verb}`

| Domain | Actions |
|---|---|
| **accounts** | `account.login`, `account.logout`, `account.register`, `account.password_reset_request`, `account.password_reset_complete`, `account.email_verify`, `account.mfa_enable`, `account.mfa_disable`, `account.profile_update`, `account.profile_delete`, `account.oauth_link`, `account.oauth_unlink`, `account.session_revoke` |
| **teams** | `team.create`, `team.update`, `team.delete`, `team.member_add`, `team.member_update`, `team.member_remove`, `team.invitation_create`, `team.invitation_delete`, `team.permission_update` |
| **devices** | `device.create`, `device.update`, `device.delete` |
| **voice** | `voice.extension_create`, `voice.extension_update`, `voice.extension_delete`, `voice.phone_number_create`, `voice.phone_number_update`, `voice.phone_number_delete`, `voice.forwarding_rule_create`, `voice.forwarding_rule_update`, `voice.forwarding_rule_delete`, `voice.voicemail_update`, `voice.voicemail_delete`, `voice.dnd_toggle` |
| **fax** | `fax.number_create`, `fax.number_update`, `fax.number_delete`, `fax.email_route_create`, `fax.email_route_update`, `fax.email_route_delete`, `fax.message_delete` |
| **support** | `support.ticket_create`, `support.ticket_update`, `support.ticket_delete`, `support.ticket_assign`, `support.ticket_status_change`, `support.message_create`, `support.message_update`, `support.message_delete`, `support.attachment_create`, `support.attachment_delete` |
| **locations** | `location.create`, `location.update`, `location.delete` |
| **connections** | `connection.create`, `connection.update`, `connection.delete` |
| **organizations** | `organization.settings_update` |
| **admin** | `admin.user_update`, `admin.user_delete`, `admin.team_update`, `admin.team_delete` |

### 4. Implementation Approach: Direct Service Calls

Rather than relying on the async event/listener system (which lacks request context and makes before/after capture difficult), add audit logging directly in each controller's action methods. This ensures:

- Access to the `request` object (for IP, user-agent)
- Access to `current_user` (for actor details)
- Ability to capture "before" state by reading the entity before mutation
- Transactional consistency (audit log written in the same request lifecycle)

**Pattern for each controller action:**

```python
# UPDATE example
@patch(...)
async def update_device(self, ..., data: DeviceUpdate) -> Device:
    before = service.capture_snapshot(await service.get(device_id))
    db_obj = await service.update(item_id=device_id, data=data.to_dict())
    after = service.capture_snapshot(db_obj)
    await service.log_audit("device.update", actor=current_user, target=db_obj, before=before, after=after, request=request)
    return service.to_schema(db_obj, schema_type=Device)

# CREATE example
@post(...)
async def create_device(self, ..., data: DeviceCreate) -> Device:
    db_obj = await service.create(data.to_dict())
    after = service.capture_snapshot(db_obj)
    await service.log_audit("device.create", actor=current_user, target=db_obj, after=after, request=request)
    return service.to_schema(db_obj, schema_type=Device)

# DELETE example
@delete(...)
async def delete_device(self, ...) -> None:
    db_obj = await service.get(device_id)
    before = service.capture_snapshot(db_obj)
    await service.delete(device_id)
    await service.log_audit("device.delete", actor=current_user, target=db_obj, before=before, request=request)
```

### 5. AuditLogService Enhancements

Extend `src/py/app/domain/admin/services/_audit.py`:

- Remove the individual `log_admin_user_update`, `log_admin_team_update`, etc. convenience methods (replaced by generic `log_audit` in the mixin)
- Add `get_entity_history(target_type, target_id)` — returns audit trail for a specific entity
- Add `get_actions_summary(hours)` — enhanced stats grouped by domain and action
- Keep `count_recent_actions()` for rate-limiting use cases

### 6. Frontend Enhancements

#### 6a. Audit Log Detail View

Add a detail drawer/modal when clicking an audit log row in `audit-log-table.tsx`:
- Show all metadata (actor, timestamp, IP, user-agent)
- Render before/after diff as a side-by-side or inline comparison
- Color-code: green for added fields, red for removed, yellow for changed
- For create actions: show all initial values
- For delete actions: show the final state that was removed

#### 6b. Entity Activity Tab

Add an "Activity" tab or section to entity detail pages (device detail, team detail, ticket detail, etc.) that shows the audit trail for that specific entity, using the `GET /api/admin/audit/target/{target_type}/{target_id}` endpoint.

#### 6c. Enhanced Filters

Improve the audit log table filters:
- Domain dropdown (accounts, teams, devices, voice, fax, support, etc.)
- Action type dropdown (create, update, delete)
- Date range picker (instead of raw ISO input)
- Actor autocomplete (search by email)

## Implementation Plan

### Phase 1: Core Infrastructure
1. Create `src/py/app/lib/audit.py` with `AuditMixin` class
2. Update `AuditLogService` to remove legacy convenience methods, add new query helpers
3. Add `request` parameter to controller dependencies where missing

### Phase 2: Wire Up All Domains (one domain at a time)
4. **accounts** — login/logout/register/password flows, profile update/delete, MFA, OAuth, sessions
5. **teams** — CRUD, members, invitations, permissions
6. **devices** — CRUD
7. **voice** — extensions, phone numbers, forwarding rules, voicemail, DND
8. **fax** — numbers, email routes, messages
9. **support** — tickets, messages, attachments, assignment, status changes
10. **locations** — CRUD
11. **connections** — CRUD
12. **organizations** — settings updates
13. **admin** — refactor existing admin audit calls to use the new mixin pattern

### Phase 3: Frontend
14. Add audit log detail view with before/after diff rendering
15. Add entity activity tabs to detail pages
16. Enhance audit log table filters (dropdowns, date picker, actor search)
17. Regenerate API client types

### Phase 4: Validation
18. Verify audit entries are written for every action across all domains
19. Verify before/after snapshots are accurate and complete
20. Test that the diff view renders correctly for all action types

## Files to Create
- `src/py/app/lib/audit.py` — AuditMixin class

## Files to Modify

### Backend
- `src/py/app/domain/admin/services/_audit.py` — enhanced query methods
- `src/py/app/domain/accounts/controllers/_access.py` — login, logout, register, password reset, sessions
- `src/py/app/domain/accounts/controllers/_profile.py` — profile update, delete
- `src/py/app/domain/accounts/controllers/_mfa.py` — MFA enable/disable
- `src/py/app/domain/accounts/controllers/_oauth_accounts.py` — OAuth link/unlink
- `src/py/app/domain/accounts/controllers/_email_verification.py` — email verification
- `src/py/app/domain/teams/controllers/_team.py` — team CRUD
- `src/py/app/domain/teams/controllers/_team_member.py` — member add/update/remove
- `src/py/app/domain/teams/controllers/_team_invitation.py` — invitation create/delete
- `src/py/app/domain/teams/controllers/_team_role_permission.py` — permission updates
- `src/py/app/domain/devices/controllers/_device.py` — device CRUD
- `src/py/app/domain/voice/controllers/_extension.py` — extension CRUD
- `src/py/app/domain/voice/controllers/_phone_number.py` — phone number CRUD
- `src/py/app/domain/voice/controllers/_forwarding.py` — forwarding rule CRUD
- `src/py/app/domain/voice/controllers/_voicemail.py` — voicemail update/delete
- `src/py/app/domain/voice/controllers/_dnd.py` — DND toggle
- `src/py/app/domain/fax/controllers/_fax_number.py` — fax number CRUD
- `src/py/app/domain/fax/controllers/_fax_email_route.py` — email route CRUD
- `src/py/app/domain/fax/controllers/_fax_message.py` — message delete
- `src/py/app/domain/support/controllers/_ticket.py` — ticket CRUD
- `src/py/app/domain/support/controllers/_ticket_message.py` — message CRUD
- `src/py/app/domain/support/controllers/_ticket_attachment.py` — attachment create/delete
- `src/py/app/domain/locations/controllers/_location.py` — location CRUD
- `src/py/app/domain/connections/controllers/_connection.py` — connection CRUD
- `src/py/app/domain/organizations/controllers/_organization.py` — settings update
- `src/py/app/domain/admin/controllers/_users.py` — refactor to use mixin
- `src/py/app/domain/admin/controllers/_teams.py` — refactor to use mixin

### Frontend
- `src/js/web/src/components/admin/audit-log-table.tsx` — add detail view, enhanced filters
- `src/js/web/src/routes/_app/admin/audit.tsx` — layout updates for detail panel
- `src/js/web/src/lib/api/hooks/admin.ts` — add hook for single audit log detail fetch
- Entity detail pages (devices, teams, voice, fax, support, etc.) — add activity tabs
