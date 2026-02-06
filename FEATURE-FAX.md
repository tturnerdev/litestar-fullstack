# Feature: Fax Management

## Summary

The Fax feature area allows users to manage their fax numbers and configure email delivery for incoming faxes. Users can view their assigned fax numbers, set destination email addresses, view fax history, and control per-number settings.

---

## Domain Module

**Backend**: `src/py/app/domain/fax/`
**Frontend**: `src/js/web/src/routes/_app/fax/` + `src/js/web/src/components/fax/`

---

## Database Models

### `FaxNumber`

A fax DID assigned to a user.

| Column | Type | Description |
|---|---|---|
| `id` | `UUIDv7` | Primary key |
| `user_id` | `UUIDv7 FK` | Owner |
| `team_id` | `UUIDv7 FK (nullable)` | Team assignment (shared fax lines) |
| `number` | `String(20)` | E.164 formatted fax number |
| `label` | `String(100) (nullable)` | User-defined label ("Main Fax", "Billing Dept") |
| `is_active` | `Boolean` | Whether fax number is receiving |
| `created_at` | `DateTimeUTC` | Auto |
| `updated_at` | `DateTimeUTC` | Auto |

**File**: `src/py/app/db/models/_fax_number.py`

### `FaxEmailRoute`

Maps a fax number to one or more email delivery addresses.

| Column | Type | Description |
|---|---|---|
| `id` | `UUIDv7` | Primary key |
| `fax_number_id` | `UUIDv7 FK` | Parent fax number |
| `email_address` | `String(320)` | Destination email (RFC 5321 max length) |
| `is_active` | `Boolean` | Whether this route is active |
| `notify_on_failure` | `Boolean` | Email notification on delivery failure |
| `created_at` | `DateTimeUTC` | Auto |
| `updated_at` | `DateTimeUTC` | Auto |

**File**: `src/py/app/db/models/_fax_email_route.py`

### `FaxMessage`

Record of a sent or received fax.

| Column | Type | Description |
|---|---|---|
| `id` | `UUIDv7` | Primary key |
| `fax_number_id` | `UUIDv7 FK` | Associated fax number |
| `direction` | `Enum` | `inbound`, `outbound` |
| `remote_number` | `String(20)` | The other party's fax number |
| `remote_name` | `String(100) (nullable)` | Remote party name (if available) |
| `page_count` | `Integer` | Number of pages |
| `status` | `Enum` | `received`, `delivered`, `failed`, `sending`, `sent` |
| `file_path` | `String(500)` | Path to stored PDF/TIFF |
| `file_size_bytes` | `BigInteger` | File size |
| `error_message` | `String(500) (nullable)` | Error details if failed |
| `delivered_to_emails` | `ARRAY(String) (nullable)` | Emails that received this fax |
| `received_at` | `DateTimeUTC` | When fax was received/sent |
| `created_at` | `DateTimeUTC` | Auto |
| `updated_at` | `DateTimeUTC` | Auto |

**File**: `src/py/app/db/models/_fax_message.py`

---

## Backend Structure

```
src/py/app/domain/fax/
├── __init__.py
├── controllers/
│   ├── __init__.py
│   ├── _fax_number.py
│   ├── _fax_email_route.py
│   └── _fax_message.py
├── services/
│   ├── __init__.py
│   ├── _fax_number.py
│   ├── _fax_email_route.py
│   └── _fax_message.py
├── schemas/
│   ├── __init__.py
│   ├── _fax_number.py
│   ├── _fax_email_route.py
│   └── _fax_message.py
├── deps.py
├── guards.py
└── listeners.py
```

### API Endpoints

#### Fax Numbers

| Method | Path | Operation | Description |
|---|---|---|---|
| `GET` | `/api/fax/numbers` | `ListFaxNumbers` | List user's fax numbers |
| `GET` | `/api/fax/numbers/{id}` | `GetFaxNumber` | Get fax number details + email routes |
| `PATCH` | `/api/fax/numbers/{id}` | `UpdateFaxNumber` | Update label, active status |

#### Email Routes

| Method | Path | Operation | Description |
|---|---|---|---|
| `GET` | `/api/fax/numbers/{fax_id}/email-routes` | `ListFaxEmailRoutes` | List email routes for a number |
| `POST` | `/api/fax/numbers/{fax_id}/email-routes` | `CreateFaxEmailRoute` | Add email route |
| `PATCH` | `/api/fax/numbers/{fax_id}/email-routes/{route_id}` | `UpdateFaxEmailRoute` | Update route (email, active) |
| `DELETE` | `/api/fax/numbers/{fax_id}/email-routes/{route_id}` | `DeleteFaxEmailRoute` | Remove email route |

#### Fax Messages / History

| Method | Path | Operation | Description |
|---|---|---|---|
| `GET` | `/api/fax/messages` | `ListFaxMessages` | List all fax messages (paginated, filterable) |
| `GET` | `/api/fax/messages/{id}` | `GetFaxMessage` | Get message details |
| `GET` | `/api/fax/messages/{id}/download` | `DownloadFaxDocument` | Download fax PDF/TIFF |
| `DELETE` | `/api/fax/messages/{id}` | `DeleteFaxMessage` | Delete a fax message |
| `POST` | `/api/fax/send` | `SendFax` | Send a fax (upload document) |

### Guards

- `requires_fax_number_access` — User owns the fax number or has team access.
- `requires_fax_message_access` — User has access to the fax number this message belongs to.

### Service Logic

- **Email Delivery**: When a fax is received, look up active `FaxEmailRoute` entries and dispatch emails with the fax document as a PDF attachment via SAQ.
- **Send Fax**: Accept uploaded PDF, validate, queue via SAQ for transmission.
- **Retry on Failure**: Failed email deliveries should retry with backoff (SAQ retry config).

### Event Listeners

- `fax_received` — Look up email routes, queue email delivery jobs.
- `fax_delivery_failed` — If `notify_on_failure` is set, send failure notification email.
- `fax_sent` — Log audit event, update message status.

---

## Frontend Structure

```
src/js/web/src/
├── routes/_app/fax/
│   ├── index.tsx                       # Fax overview / dashboard
│   ├── numbers/
│   │   ├── index.tsx                   # Fax number list
│   │   └── $faxNumberId/
│   │       └── index.tsx               # Number settings + email routes
│   ├── messages/
│   │   ├── index.tsx                   # Fax message history
│   │   └── $messageId/
│   │       └── index.tsx               # Message detail / viewer
│   └── send.tsx                        # Send fax form
├── components/fax/
│   ├── fax-number-list.tsx
│   ├── fax-number-card.tsx
│   ├── email-route-editor.tsx          # Add/edit/remove email routes
│   ├── email-route-row.tsx
│   ├── fax-message-list.tsx            # Message history table
│   ├── fax-message-detail.tsx          # Message viewer with PDF preview
│   ├── fax-send-form.tsx              # Upload and send fax
│   └── fax-status-badge.tsx            # Status indicator
└── lib/api/hooks/fax.ts
```

### Pages

#### Fax Overview (`/fax`)
- Summary cards: number of fax numbers, recent messages, undelivered count.
- Quick links to numbers, messages, and send fax.

#### Fax Numbers (`/fax/numbers`)
- List of assigned fax numbers with labels and active status.
- Click to manage email routes.

#### Fax Number Settings (`/fax/numbers/:id`)
- **Details section**: Number, label, active toggle.
- **Email Routes section**: Table of email addresses with add/edit/remove.
  - Each row: email address, active toggle, notify-on-failure toggle, delete button.
  - "Add Email" button with email validation.

#### Fax Messages (`/fax/messages`)
- Filterable/sortable table: date, direction (in/out), remote number, pages, status.
- Filter by fax number, date range, direction, status.
- Click to view detail.

#### Fax Message Detail (`/fax/messages/:id`)
- Metadata: date, direction, remote party, pages, status.
- Inline PDF viewer for the fax document.
- Download button.
- Delete button with confirmation.

#### Send Fax (`/fax/send`)
- Select source fax number.
- Enter destination number.
- Upload PDF document.
- Preview before sending.
- Submit queues the fax for transmission.

### React Query Hooks

```typescript
// lib/api/hooks/fax.ts
useFaxNumbers()
useFaxNumber(id)
useUpdateFaxNumber(id)

useFaxEmailRoutes(faxNumberId)
useCreateFaxEmailRoute(faxNumberId)
useUpdateFaxEmailRoute(faxNumberId, routeId)
useDeleteFaxEmailRoute(faxNumberId, routeId)

useFaxMessages(filters)
useFaxMessage(id)
useDeleteFaxMessage(id)
useDownloadFaxDocument(id)
useSendFax()
```

---

## Sub-Features & Tasks

### Phase 1: Fax Numbers & Email Routes
- [ ] Create `FaxNumber` and `FaxEmailRoute` database models
- [ ] Create Alembic migration
- [ ] Implement `FaxNumberService` with CRUD
- [ ] Implement `FaxEmailRouteService` with CRUD
- [ ] Implement controllers for both
- [ ] Create schemas
- [ ] Add guards and dependency providers
- [ ] Build fax number list UI
- [ ] Build email route editor UI

### Phase 2: Fax Message History
- [ ] Create `FaxMessage` database model
- [ ] Create Alembic migration
- [ ] Implement `FaxMessageService` with list/get/delete
- [ ] Implement controller with pagination and filtering
- [ ] Build fax message list UI with filters
- [ ] Build fax message detail view with PDF preview
- [ ] Implement document download endpoint

### Phase 3: Inbound Fax Processing
- [ ] Implement `fax_received` event listener
- [ ] Implement email delivery via SAQ background task
- [ ] Implement retry logic for failed deliveries
- [ ] Implement `fax_delivery_failed` notification
- [ ] Add email templates for fax delivery (React Email)

### Phase 4: Send Fax
- [ ] Implement fax send endpoint with file upload
- [ ] Implement SAQ background task for fax transmission
- [ ] Build send fax form with PDF upload and preview
- [ ] Implement `fax_sent` event listener
- [ ] Add validation (PDF format, page limit, number format)

### Phase 5: Admin Views
- [ ] Add `/admin/fax` management page
- [ ] View all fax numbers across users
- [ ] View system-wide fax delivery statistics
- [ ] Add audit log entries for fax operations
