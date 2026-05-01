# FEATURE-UCAAS.md — UCaaS Feature Enhancements

## Overview

This plan covers UCaaS (Unified Communications as a Service) features to enhance the admin portal beyond basic phone/fax/device management. Features are organized by implementation phase, prioritizing the most impactful additions that build on the existing domain architecture.

---

## Phase 1 — Call Routing & Schedules

### 1a. Business Hours & Holiday Schedules

**New domain: `schedules`** at `src/py/app/domain/schedules/`

**Model: `Schedule`**
- `id` (UUIDv7)
- `team_id` (FK)
- `name` (str) — e.g., "Main Office Hours"
- `timezone` (str) — e.g., "America/Chicago"
- `is_default` (bool)
- `schedule_type` (enum: `business_hours`, `holiday`, `custom`)

**Model: `ScheduleEntry`**
- `id` (UUIDv7)
- `schedule_id` (FK)
- `day_of_week` (int, 0-6, nullable for holidays)
- `start_time` (time)
- `end_time` (time)
- `date` (date, nullable — for specific holiday dates)
- `label` (str, nullable) — e.g., "Christmas Day"
- `is_closed` (bool) — marks a full-day closure

**API Endpoints:**
- `GET/POST /api/schedules` — list/create schedules
- `GET/PUT/DELETE /api/schedules/{id}` — CRUD
- `GET/POST /api/schedules/{id}/entries` — manage time entries
- `GET /api/schedules/{id}/check?time={iso}` — check if a given time is in/out of hours

**Frontend:**
- Schedule list page at `/schedules`
- Schedule detail page with visual weekly calendar editor
- Holiday calendar with date picker
- "Check Now" button showing current open/closed status

**Complexity:** M | **Priority:** P1

---

### 1b. Time Conditions & Call Routing Rules

**New domain: `call-routing`** at `src/py/app/domain/call_routing/`

**Model: `TimeCondition`**
- `id` (UUIDv7)
- `team_id` (FK)
- `name` (str)
- `schedule_id` (FK → Schedule)
- `match_destination` (str) — where to route when schedule is "open"
- `no_match_destination` (str) — where to route when "closed"
- `override_mode` (enum: `none`, `force_match`, `force_no_match`) — manual night mode toggle

**Model: `IvrMenu` (Auto-Attendant)**
- `id` (UUIDv7)
- `team_id` (FK)
- `name` (str) — e.g., "Main Menu"
- `greeting_type` (enum: `tts`, `upload`, `none`)
- `greeting_text` (str, nullable) — TTS text
- `greeting_file_url` (str, nullable) — uploaded audio
- `timeout_seconds` (int, default 5)
- `max_retries` (int, default 3)
- `timeout_destination` (str)
- `invalid_destination` (str)

**Model: `IvrMenuOption`**
- `id` (UUIDv7)
- `ivr_menu_id` (FK)
- `digit` (str) — "0"-"9", "*", "#"
- `label` (str) — e.g., "Sales"
- `destination` (str) — destination in Asterisk format
- `sort_order` (int)

**Model: `CallQueue`**
- `id` (UUIDv7)
- `team_id` (FK)
- `name` (str)
- `number` (str) — queue access number
- `strategy` (enum: `ring_all`, `round_robin`, `longest_idle`, `linear_hunt`, `random`)
- `ring_time` (int, default 15)
- `max_wait_time` (int, default 300)
- `max_callers` (int, default 10)
- `join_empty` (bool, default false)
- `leave_when_empty` (bool, default true)
- `music_on_hold_class` (str, nullable)
- `announce_frequency` (int, nullable) — seconds between position announcements
- `announce_holdtime` (bool, default false)
- `timeout_destination` (str, nullable)
- `wrapup_time` (int, default 0)

**Model: `CallQueueMember`**
- `id` (UUIDv7)
- `call_queue_id` (FK)
- `extension_id` (FK → Extension)
- `priority` (int, default 0)
- `penalty` (int, default 0)
- `is_paused` (bool, default false)

**Model: `RingGroup`**
- `id` (UUIDv7)
- `team_id` (FK)
- `name` (str)
- `number` (str) — group access number
- `strategy` (enum: `ring_all`, `round_robin`, `linear_hunt`)
- `ring_time` (int, default 20)
- `no_answer_destination` (str, nullable)

**Model: `RingGroupMember`**
- `id` (UUIDv7)
- `ring_group_id` (FK)
- `extension_id` (FK, nullable)
- `external_number` (str, nullable) — for external numbers in the group
- `sort_order` (int)

**API Endpoints:**
- Full CRUD for time conditions, IVR menus, call queues, ring groups
- `POST /api/call-queues/{id}/members` — manage queue membership
- `PUT /api/call-queues/{id}/members/{member_id}/pause` — pause/unpause agent
- `PUT /api/time-conditions/{id}/override` — toggle night mode

**Frontend:**
- `/call-routing` — tabbed list view for Time Conditions, IVR Menus, Call Queues, Ring Groups
- IVR menu editor with digit-to-destination mapping table
- Call queue editor with drag-to-reorder member list
- Ring group editor with member picker
- Time condition editor linking to schedule with night mode toggle

**Complexity:** L | **Priority:** P1

---

## Phase 2 — Analytics & CDR

### 2a. Call Detail Records

**New domain: `analytics`** at `src/py/app/domain/analytics/`

**Model: `CallRecord`**
- `id` (UUIDv7)
- `team_id` (FK)
- `call_date` (datetime)
- `caller_id` (str)
- `source` (str) — source number/extension
- `destination` (str)
- `duration` (int) — seconds
- `billable_seconds` (int)
- `direction` (enum: `inbound`, `outbound`, `internal`)
- `disposition` (enum: `answered`, `no_answer`, `busy`, `failed`, `voicemail`)
- `channel` (str, nullable)
- `unique_id` (str) — provider-side unique identifier
- `recording_url` (str, nullable)
- `cost` (decimal, nullable)
- `connection_id` (FK, nullable) — which provider/trunk

**API Endpoints:**
- `GET /api/analytics/cdrs` — paginated, filterable CDR list
  - Filters: date range, direction, disposition, source, destination, extension, duration range
  - Sort: date, duration, cost
- `GET /api/analytics/cdrs/{id}` — single CDR detail
- `GET /api/analytics/cdrs/export` — CSV/PDF export

**Frontend:**
- `/analytics/cdrs` — searchable, filterable CDR table with date range picker
- CDR detail view with call timeline
- Export button (CSV)

**Complexity:** M | **Priority:** P1

### 2b. Call Analytics Dashboard

**API Endpoints:**
- `GET /api/analytics/summary` — aggregate metrics for a date range
  - `total_calls`, `answered`, `missed`, `voicemail`, `avg_duration`, `avg_wait_time`
- `GET /api/analytics/volume` — call volume by hour/day/week for charting
- `GET /api/analytics/top-callers` — most frequent callers
- `GET /api/analytics/by-extension` — per-extension call stats
- `GET /api/analytics/by-queue` — per-queue metrics (SLA %, abandon rate, avg wait)

**Frontend:**
- `/analytics` — dashboard with summary cards and charts
- Line chart: call volume over time
- Bar chart: calls by extension / by queue
- Pie chart: disposition breakdown (answered/missed/voicemail)
- Stat cards: total calls, avg duration, answer rate
- Date range picker and filters

**Complexity:** L | **Priority:** P1

---

## Phase 3 — Enhanced Voice Features

### 3a. Call Forwarding Rules

Extend the existing `voice` domain's Extension model.

**Model: `ForwardingRule` (or fields on Extension)**
- `forward_always_enabled` (bool)
- `forward_always_destination` (str, nullable)
- `forward_busy_enabled` (bool)
- `forward_busy_destination` (str, nullable)
- `forward_no_answer_enabled` (bool)
- `forward_no_answer_destination` (str, nullable)
- `forward_no_answer_ring_count` (int, default 4)
- `forward_unreachable_enabled` (bool)
- `forward_unreachable_destination` (str, nullable)
- `do_not_disturb` (bool, default false)

**Frontend:**
- Add "Call Forwarding" card to extension detail page
- Toggle switches for each forwarding type with destination input
- DND toggle

**Complexity:** M | **Priority:** P1

### 3b. Voicemail Management

Extend the existing `voice` domain.

**Model: `VoicemailBox`**
- `id` (UUIDv7)
- `extension_id` (FK)
- `pin` (str, encrypted)
- `email_address` (str, nullable) — notification email
- `email_attachment` (bool, default true) — attach audio to email
- `transcription_enabled` (bool, default false)
- `greeting_type` (enum: `default`, `busy`, `unavailable`, `custom`)
- `greeting_file_url` (str, nullable)
- `max_message_length` (int, default 180) — seconds
- `auto_delete_days` (int, nullable) — retention
- `is_enabled` (bool, default true)

**Model: `VoicemailMessage`**
- `id` (UUIDv7)
- `voicemail_box_id` (FK)
- `caller_id` (str)
- `duration` (int) — seconds
- `received_at` (datetime)
- `is_read` (bool, default false)
- `is_urgent` (bool, default false)
- `audio_url` (str)
- `transcription` (str, nullable)

**API Endpoints:**
- `GET/PUT /api/voicemail/boxes/{extension_id}` — voicemail config
- `GET /api/voicemail/messages` — list messages (filterable by box, read status)
- `GET /api/voicemail/messages/{id}` — single message with audio URL
- `PUT /api/voicemail/messages/{id}/read` — mark read/unread
- `DELETE /api/voicemail/messages/{id}` — delete message

**Frontend:**
- "Voicemail" tab on extension detail page
- Voicemail settings card (PIN, email, transcription toggle)
- Voicemail inbox with audio player, read/unread badges, transcription display
- `/voicemail` — admin-wide voicemail message list

**Complexity:** L | **Priority:** P1

### 3c. Music on Hold

**Model: `MusicOnHold`**
- `id` (UUIDv7)
- `team_id` (FK)
- `name` (str) — e.g., "Default", "Holiday Music"
- `is_default` (bool)

**Model: `MusicOnHoldFile`**
- `id` (UUIDv7)
- `music_on_hold_id` (FK)
- `filename` (str)
- `file_url` (str)
- `sort_order` (int)
- `duration` (int) — seconds

**Frontend:**
- `/settings/music-on-hold` — manage music classes
- Upload audio files, reorder playlist, preview playback
- Assignable on call queues and ring groups

**Complexity:** S | **Priority:** P2

---

## Phase 4 — E911 & Emergency Services

### 4a. E911 Address Management

Extend the existing `locations` domain.

**Add to Location model or new model `E911Registration`:**
- `id` (UUIDv7)
- `phone_number_id` (FK)
- `location_id` (FK, nullable)
- `address_line_1` (str)
- `address_line_2` (str, nullable)
- `city` (str)
- `state` (str)
- `postal_code` (str)
- `country` (str, default "US")
- `validated` (bool) — MSAG validation status
- `validated_at` (datetime, nullable)
- `carrier_registration_id` (str, nullable) — Telnyx/carrier-side ID

**API Endpoints:**
- `GET/POST /api/e911` — list/create E911 registrations
- `GET/PUT/DELETE /api/e911/{id}`
- `POST /api/e911/{id}/validate` — validate against carrier MSAG
- `GET /api/e911/unregistered` — phone numbers without E911 addresses

**Frontend:**
- `/e911` — E911 registration list with validation status badges
- Bulk assign addresses to numbers from location records
- Warning indicators on phone numbers without E911 registration

**Complexity:** M | **Priority:** P1

---

## Phase 5 — Messaging

### 5a. Business SMS/MMS

**New domain: `messaging`** at `src/py/app/domain/messaging/`

**Model: `SmsMessage`**
- `id` (UUIDv7)
- `team_id` (FK)
- `phone_number_id` (FK) — sending/receiving number
- `direction` (enum: `inbound`, `outbound`)
- `from_number` (str)
- `to_number` (str)
- `body` (str)
- `media_urls` (list[str], nullable) — MMS attachments
- `status` (enum: `queued`, `sent`, `delivered`, `failed`, `received`)
- `segment_count` (int, default 1)
- `carrier_message_id` (str, nullable)
- `sent_at` (datetime, nullable)
- `delivered_at` (datetime, nullable)
- `error_message` (str, nullable)
- `cost` (decimal, nullable)

**Model: `SmsConversation`**
- `id` (UUIDv7)
- `team_id` (FK)
- `phone_number_id` (FK) — our number
- `contact_number` (str) — the other party
- `last_message_at` (datetime)
- `unread_count` (int, default 0)

**API Endpoints:**
- `GET /api/messaging/conversations` — conversation list
- `GET /api/messaging/conversations/{id}/messages` — messages in a conversation
- `POST /api/messaging/send` — send SMS/MMS
- `GET /api/messaging/messages` — all messages (admin view)

**Frontend:**
- `/messaging` — conversation list with unread badges
- Conversation detail view with chat-style message thread
- Compose new message dialog
- Message status indicators (sent/delivered/failed)

**Complexity:** L | **Priority:** P2

---

## Phase 6 — User & Access Enhancements

### 6a. RBAC Enhancements

Extend `accounts` domain.

**Model: `Permission`**
- `id` (UUIDv7)
- `name` (str) — e.g., "devices.edit", "analytics.view"
- `description` (str)
- `category` (str) — e.g., "devices", "voice", "admin"

**Model: `RolePermission`** (M2M)
- `role_id` (FK)
- `permission_id` (FK)

**Frontend:**
- Permission matrix editor in admin → roles page
- Checkbox grid: roles × permissions by category

**Complexity:** M | **Priority:** P2

### 6b. Bulk Operations

**API Endpoints:**
- `POST /api/bulk/users/import` — CSV upload for user creation
- `POST /api/bulk/devices/import` — CSV upload for device provisioning
- `POST /api/bulk/numbers/import` — CSV upload for number assignment
- `GET /api/bulk/jobs/{id}` — job status with progress and error details

**Frontend:**
- Bulk import dialog accessible from list page headers
- CSV template download
- Upload with validation preview (show what will be created/updated)
- Progress indicator and error report

**Complexity:** M | **Priority:** P2

---

## Phase 7 — Device Enhancements

### 7a. Device Templates

**Model: `DeviceTemplate`**
- `id` (UUIDv7)
- `team_id` (FK)
- `name` (str) — e.g., "Standard Desk Phone"
- `manufacturer` (str, nullable)
- `model_pattern` (str, nullable) — regex to auto-match devices
- `line_key_config` (jsonb) — line key layout template
- `codec_preferences` (list[str], nullable)
- `settings_override` (jsonb) — device settings template

**Frontend:**
- `/devices/templates` — template list
- Template editor with line key visual layout
- "Apply Template" action on device detail pages

**Complexity:** M | **Priority:** P2

### 7b. Firmware Management

**Model: `FirmwareVersion`**
- `id` (UUIDv7)
- `manufacturer` (str)
- `model` (str)
- `version` (str)
- `file_url` (str)
- `release_notes` (str, nullable)
- `is_current` (bool) — recommended version
- `released_at` (datetime)

**Frontend:**
- `/devices/firmware` — firmware inventory
- Per-device firmware status (current/outdated)
- "Push Update" action for individual devices or bulk

**Complexity:** M | **Priority:** P3

---

## Phase 8 — Webhooks & Notifications

### 8a. Webhook Management

**New domain: `webhooks`** at `src/py/app/domain/webhooks/`

**Model: `WebhookEndpoint`**
- `id` (UUIDv7)
- `team_id` (FK)
- `name` (str)
- `url` (str)
- `secret` (str) — HMAC signing secret
- `events` (list[str]) — subscribed event types
- `is_active` (bool)
- `last_triggered_at` (datetime, nullable)
- `failure_count` (int, default 0)

**Model: `WebhookDelivery`**
- `id` (UUIDv7)
- `webhook_endpoint_id` (FK)
- `event_type` (str)
- `payload` (jsonb)
- `response_status` (int, nullable)
- `response_body` (str, nullable)
- `delivered_at` (datetime)
- `success` (bool)
- `retry_count` (int, default 0)

**Event types:**
- `call.completed`, `call.missed`, `call.recording_ready`
- `voicemail.received`
- `device.offline`, `device.online`
- `fax.received`, `fax.sent`
- `sms.received`, `sms.sent`
- `extension.created`, `extension.deleted`
- `number.assigned`, `number.unassigned`

**Frontend:**
- `/settings/webhooks` — webhook endpoint list
- Endpoint editor with event type checkboxes
- Delivery log with response details and retry button
- Test webhook button (sends sample payload)

**Complexity:** M | **Priority:** P2

### 8b. Notification Preferences (Admin Alerts)

Extend existing notification preferences.

**Alert types:**
- Device went offline (configurable: any device, specific devices)
- Call queue SLA breach (wait time exceeds threshold)
- Trunk/connection failure
- High call abandonment rate
- Fax delivery failure

**Delivery channels:** Email, in-app notification

**Frontend:**
- `/settings/notifications` — alert rule configuration
- Per-alert toggle, threshold inputs, recipient selection

**Complexity:** M | **Priority:** P2

---

## Implementation Order

| Batch | Phase | Items | Est. Complexity |
|-------|-------|-------|-----------------|
| 1 | 1a | Business Hours & Holiday Schedules | M |
| 2 | 1b | Time Conditions, IVR Menus (models + API only) | L |
| 3 | 1b | Call Queues, Ring Groups (models + API only) | L |
| 4 | 1b | Call Routing frontend (all 4 entity types) | L |
| 5 | 2a | CDR model + API + frontend | M |
| 6 | 2b | Analytics dashboard (summary + charts) | L |
| 7 | 3a | Call Forwarding rules | M |
| 8 | 3b | Voicemail management (model + API + frontend) | L |
| 9 | 3c | Music on Hold | S |
| 10 | 4a | E911 address management | M |
| 11 | 5a | Business SMS/MMS (model + API + frontend) | L |
| 12 | 6a | RBAC permission matrix | M |
| 13 | 6b | Bulk import operations | M |
| 14 | 7a | Device templates | M |
| 15 | 8a | Webhook management | M |
| 16 | 8b | Notification alert rules | M |

---

## References

- RingCentral Admin Portal features
- Nextiva UCaaS feature set (27 must-have features)
- Zoom Phone Auto Receptionist & IVR
- Microsoft Teams Phone call routing
- GoTo Connect PBX admin tools
- 8x8 CDR and call quality analytics
- Dialpad web portal and call monitoring
- Telnyx number management and porting
- E911/RAY BAUM's Act requirements for VoIP
