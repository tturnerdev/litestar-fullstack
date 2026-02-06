# Feature: Voice Settings

## Summary

The Voice feature area provides users with configuration for telephony services: phone numbers, extensions, voicemail, call forwarding rules, and Do Not Disturb (DND) mode. These settings directly control how incoming and outgoing calls are routed.

---

## Domain Module

**Backend**: `src/py/app/domain/voice/`
**Frontend**: `src/js/web/src/routes/_app/voice/` + `src/js/web/src/components/voice/`

---

## Database Models

### `PhoneNumber`

Represents a DID (Direct Inward Dial) number assigned to a user.

| Column | Type | Description |
|---|---|---|
| `id` | `UUIDv7` | Primary key |
| `user_id` | `UUIDv7 FK` | Owner |
| `number` | `String(20)` | E.164 formatted number (e.g., "+15551234567") |
| `label` | `String(100) (nullable)` | User-defined label ("Main Line", "Sales") |
| `number_type` | `Enum` | `local`, `toll_free`, `international` |
| `caller_id_name` | `String(50) (nullable)` | Outbound caller ID name |
| `is_active` | `Boolean` | Whether number is active |
| `team_id` | `UUIDv7 FK (nullable)` | Team assignment (shared lines) |

**File**: `src/py/app/db/models/_phone_number.py`

### `Extension`

Internal extension for routing calls within the system.

| Column | Type | Description |
|---|---|---|
| `id` | `UUIDv7` | Primary key |
| `user_id` | `UUIDv7 FK` | Owner |
| `extension_number` | `String(10)` | Extension number (e.g., "1001") |
| `phone_number_id` | `UUIDv7 FK (nullable)` | Associated DID for direct inbound |
| `display_name` | `String(100)` | Display name in directory |
| `is_active` | `Boolean` | Whether extension is active |

**File**: `src/py/app/db/models/_extension.py`

### `VoicemailBox`

Voicemail configuration for an extension.

| Column | Type | Description |
|---|---|---|
| `id` | `UUIDv7` | Primary key |
| `extension_id` | `UUIDv7 FK (unique)` | One voicemail box per extension |
| `is_enabled` | `Boolean` | Voicemail on/off |
| `pin` | `String(20) (encrypted)` | Access PIN |
| `greeting_type` | `Enum` | `default`, `custom`, `name_only` |
| `greeting_file_path` | `String(500) (nullable)` | Path to custom greeting audio |
| `max_message_length_seconds` | `Integer` | Max recording length (default 120) |
| `email_notification` | `Boolean` | Send email on new voicemail |
| `email_attach_audio` | `Boolean` | Attach audio file to email |
| `transcription_enabled` | `Boolean` | Enable voicemail-to-text |
| `auto_delete_days` | `Integer (nullable)` | Auto-delete after N days (null = keep) |

**File**: `src/py/app/db/models/_voicemail_box.py`

### `VoicemailMessage`

Individual voicemail messages.

| Column | Type | Description |
|---|---|---|
| `id` | `UUIDv7` | Primary key |
| `voicemail_box_id` | `UUIDv7 FK` | Parent voicemail box |
| `caller_number` | `String(20)` | Caller's number |
| `caller_name` | `String(100) (nullable)` | Caller's name (if available) |
| `duration_seconds` | `Integer` | Message duration |
| `audio_file_path` | `String(500)` | Path to stored audio |
| `transcription` | `Text (nullable)` | Transcribed text |
| `is_read` | `Boolean` | Read/unread flag |
| `is_urgent` | `Boolean` | Urgent flag |
| `received_at` | `DateTimeUTC` | When the message was left |

**File**: `src/py/app/db/models/_voicemail_message.py`

### `ForwardingRule`

Call forwarding configuration.

| Column | Type | Description |
|---|---|---|
| `id` | `UUIDv7` | Primary key |
| `extension_id` | `UUIDv7 FK` | Extension this rule applies to |
| `rule_type` | `Enum` | `always`, `busy`, `no_answer`, `unreachable` |
| `destination_type` | `Enum` | `extension`, `external`, `voicemail` |
| `destination_value` | `String(100)` | Extension number or phone number |
| `ring_timeout_seconds` | `Integer (nullable)` | Seconds before forwarding (for `no_answer`) |
| `is_active` | `Boolean` | Whether this rule is active |
| `priority` | `Integer` | Evaluation order |

**File**: `src/py/app/db/models/_forwarding_rule.py`

### `DoNotDisturb`

DND schedule and settings.

| Column | Type | Description |
|---|---|---|
| `id` | `UUIDv7` | Primary key |
| `extension_id` | `UUIDv7 FK (unique)` | One DND config per extension |
| `is_enabled` | `Boolean` | DND currently active |
| `mode` | `Enum` | `always`, `scheduled`, `off` |
| `schedule_start` | `Time (nullable)` | Daily DND start time |
| `schedule_end` | `Time (nullable)` | Daily DND end time |
| `schedule_days` | `ARRAY(Integer) (nullable)` | Days of week (0=Mon, 6=Sun) |
| `allow_list` | `ARRAY(String) (nullable)` | Numbers that bypass DND |

**File**: `src/py/app/db/models/_do_not_disturb.py`

---

## Backend Structure

```
src/py/app/domain/voice/
├── __init__.py
├── controllers/
│   ├── __init__.py
│   ├── _phone_number.py
│   ├── _extension.py
│   ├── _voicemail.py
│   ├── _forwarding.py
│   └── _dnd.py
├── services/
│   ├── __init__.py
│   ├── _phone_number.py
│   ├── _extension.py
│   ├── _voicemail.py
│   ├── _forwarding.py
│   └── _dnd.py
├── schemas/
│   ├── __init__.py
│   ├── _phone_number.py
│   ├── _extension.py
│   ├── _voicemail.py
│   ├── _forwarding.py
│   └── _dnd.py
├── deps.py
├── guards.py
└── listeners.py
```

### API Endpoints

#### Phone Numbers

| Method | Path | Operation | Description |
|---|---|---|---|
| `GET` | `/api/voice/phone-numbers` | `ListPhoneNumbers` | List user's phone numbers |
| `GET` | `/api/voice/phone-numbers/{id}` | `GetPhoneNumber` | Get phone number details |
| `PATCH` | `/api/voice/phone-numbers/{id}` | `UpdatePhoneNumber` | Update label, caller ID |

#### Extensions

| Method | Path | Operation | Description |
|---|---|---|---|
| `GET` | `/api/voice/extensions` | `ListExtensions` | List user's extensions |
| `GET` | `/api/voice/extensions/{id}` | `GetExtension` | Get extension details + all settings |
| `PATCH` | `/api/voice/extensions/{id}` | `UpdateExtension` | Update display name, settings |

#### Voicemail

| Method | Path | Operation | Description |
|---|---|---|---|
| `GET` | `/api/voice/extensions/{ext_id}/voicemail` | `GetVoicemailSettings` | Get voicemail box config |
| `PATCH` | `/api/voice/extensions/{ext_id}/voicemail` | `UpdateVoicemailSettings` | Update voicemail settings |
| `GET` | `/api/voice/extensions/{ext_id}/voicemail/messages` | `ListVoicemailMessages` | List messages (paginated) |
| `GET` | `/api/voice/extensions/{ext_id}/voicemail/messages/{msg_id}` | `GetVoicemailMessage` | Get message details + audio URL |
| `PATCH` | `/api/voice/extensions/{ext_id}/voicemail/messages/{msg_id}` | `UpdateVoicemailMessage` | Mark read/unread |
| `DELETE` | `/api/voice/extensions/{ext_id}/voicemail/messages/{msg_id}` | `DeleteVoicemailMessage` | Delete a message |
| `POST` | `/api/voice/extensions/{ext_id}/voicemail/greeting` | `UploadVoicemailGreeting` | Upload custom greeting audio |

#### Call Forwarding

| Method | Path | Operation | Description |
|---|---|---|---|
| `GET` | `/api/voice/extensions/{ext_id}/forwarding` | `ListForwardingRules` | Get all forwarding rules |
| `PUT` | `/api/voice/extensions/{ext_id}/forwarding` | `SetForwardingRules` | Bulk replace all rules |
| `POST` | `/api/voice/extensions/{ext_id}/forwarding` | `CreateForwardingRule` | Add a rule |
| `PATCH` | `/api/voice/extensions/{ext_id}/forwarding/{rule_id}` | `UpdateForwardingRule` | Update a rule |
| `DELETE` | `/api/voice/extensions/{ext_id}/forwarding/{rule_id}` | `DeleteForwardingRule` | Remove a rule |

#### Do Not Disturb

| Method | Path | Operation | Description |
|---|---|---|---|
| `GET` | `/api/voice/extensions/{ext_id}/dnd` | `GetDndSettings` | Get DND configuration |
| `PATCH` | `/api/voice/extensions/{ext_id}/dnd` | `UpdateDndSettings` | Update DND settings |
| `POST` | `/api/voice/extensions/{ext_id}/dnd/toggle` | `ToggleDnd` | Quick toggle DND on/off |

### Guards

- `requires_extension_ownership` — User owns the extension or is superuser.
- `requires_phone_number_access` — User owns the number or has team access.

### Event Listeners

- `voicemail_received` — Send email notification with optional audio attachment.
- `forwarding_rules_changed` — Log audit event, sync to PBX/SIP server.
- `dnd_toggled` — Log audit event, update device presence indicators.

---

## Frontend Structure

```
src/js/web/src/
├── routes/_app/voice/
│   ├── index.tsx                       # Voice overview / dashboard
│   ├── phone-numbers.tsx               # Phone number list
│   ├── extensions/
│   │   ├── index.tsx                   # Extension list
│   │   └── $extensionId/
│   │       ├── index.tsx               # Extension settings (tabbed)
│   │       ├── voicemail.tsx           # Voicemail settings + messages
│   │       ├── forwarding.tsx          # Forwarding rules editor
│   │       └── dnd.tsx                 # DND configuration
├── components/voice/
│   ├── phone-number-list.tsx
│   ├── phone-number-card.tsx
│   ├── extension-list.tsx
│   ├── extension-settings-form.tsx
│   ├── voicemail-settings-form.tsx
│   ├── voicemail-message-list.tsx
│   ├── voicemail-player.tsx            # Audio player component
│   ├── forwarding-rule-editor.tsx      # Drag-and-drop rule ordering
│   ├── forwarding-rule-row.tsx
│   ├── dnd-settings-form.tsx
│   ├── dnd-schedule-picker.tsx         # Visual schedule editor
│   └── dnd-quick-toggle.tsx            # Toggle button for nav/header
└── lib/api/hooks/voice.ts
```

### Pages

#### Voice Overview (`/voice`)
- Dashboard with summary cards: number of extensions, active DND, unread voicemails.
- Quick-access links to each sub-section.

#### Phone Numbers (`/voice/phone-numbers`)
- Table of assigned phone numbers with labels and type badges.
- Inline edit for label and caller ID name.

#### Extensions (`/voice/extensions`)
- List of extensions with status indicators.
- Click to navigate to settings.

#### Extension Settings (`/voice/extensions/:id`)
- **Tabbed layout**:
  - **General**: Display name, assigned phone number, linked devices.
  - **Voicemail**: Enable/disable, PIN, greeting, email notification settings.
  - **Forwarding**: Visual rule editor with conditions and priorities.
  - **DND**: Toggle, mode selection, schedule picker, allow list.

#### Voicemail Messages (`/voice/extensions/:id/voicemail`)
- List of messages: caller, time, duration, read/unread, transcription preview.
- Inline audio player.
- Bulk actions: mark read, delete.

### React Query Hooks

```typescript
// lib/api/hooks/voice.ts
usePhoneNumbers()
usePhoneNumber(id)
useUpdatePhoneNumber(id)

useExtensions()
useExtension(id)
useUpdateExtension(id)

useVoicemailSettings(extensionId)
useUpdateVoicemailSettings(extensionId)
useVoicemailMessages(extensionId, filters)
useUpdateVoicemailMessage(extensionId, messageId)
useDeleteVoicemailMessage(extensionId, messageId)
useUploadVoicemailGreeting(extensionId)

useForwardingRules(extensionId)
useSetForwardingRules(extensionId)
useCreateForwardingRule(extensionId)
useUpdateForwardingRule(extensionId, ruleId)
useDeleteForwardingRule(extensionId, ruleId)

useDndSettings(extensionId)
useUpdateDndSettings(extensionId)
useToggleDnd(extensionId)
```

---

## Sub-Features & Tasks

### Phase 1: Phone Numbers & Extensions
- [ ] Create `PhoneNumber` and `Extension` database models
- [ ] Create Alembic migration
- [ ] Implement services and controllers for phone numbers
- [ ] Implement services and controllers for extensions
- [ ] Create all schemas
- [ ] Add guards and dependency providers
- [ ] Build phone number list UI
- [ ] Build extension list and settings UI

### Phase 2: Voicemail
- [ ] Create `VoicemailBox` and `VoicemailMessage` models
- [ ] Create Alembic migration
- [ ] Implement voicemail settings service/controller
- [ ] Implement voicemail message service/controller
- [ ] Build voicemail settings form
- [ ] Build voicemail message list with audio player
- [ ] Implement greeting file upload
- [ ] Add `voicemail_received` event listener + email notification

### Phase 3: Call Forwarding
- [ ] Create `ForwardingRule` model
- [ ] Create Alembic migration
- [ ] Implement forwarding service/controller
- [ ] Build forwarding rule editor UI (visual, drag-and-drop priority)
- [ ] Add validation: prevent circular forwarding
- [ ] Add `forwarding_rules_changed` event listener

### Phase 4: Do Not Disturb
- [ ] Create `DoNotDisturb` model
- [ ] Create Alembic migration
- [ ] Implement DND service/controller
- [ ] Build DND settings form with schedule picker
- [ ] Add quick toggle to navigation header
- [ ] Add `dnd_toggled` event listener

### Phase 5: Admin Views
- [ ] Add `/admin/voice` with overview of all extensions system-wide
- [ ] Add ability for admins to assign/unassign phone numbers
- [ ] Add audit log entries for all voice settings changes
