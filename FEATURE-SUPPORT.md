# Feature: Support / Helpdesk

## Summary

The Support feature area provides a fully integrated helpdesk system. Users can view their existing tickets, open new tickets, close tickets, and communicate with support staff. The system supports full markdown formatting and image embedding (copy/paste and file attachment) in ticket messages.

---

## Domain Module

**Backend**: `src/py/app/domain/support/`
**Frontend**: `src/js/web/src/routes/_app/support/` + `src/js/web/src/components/support/`

---

## Database Models

### `Ticket`

A support ticket.

| Column | Type | Description |
|---|---|---|
| `id` | `UUIDv7` | Primary key |
| `user_id` | `UUIDv7 FK` | Ticket creator |
| `assigned_to_id` | `UUIDv7 FK (nullable)` | Assigned support agent |
| `team_id` | `UUIDv7 FK (nullable)` | Team context (if ticket is team-related) |
| `ticket_number` | `String(20) (unique)` | Human-readable ticket number (e.g., "SUP-00142") |
| `subject` | `String(255)` | Ticket subject line |
| `status` | `Enum` | `open`, `in_progress`, `waiting_on_customer`, `waiting_on_support`, `resolved`, `closed` |
| `priority` | `Enum` | `low`, `medium`, `high`, `urgent` |
| `category` | `Enum (nullable)` | `billing`, `technical`, `account`, `device`, `voice`, `fax`, `general` |
| `is_read_by_user` | `Boolean` | User has seen latest reply |
| `is_read_by_agent` | `Boolean` | Agent has seen latest reply |
| `closed_at` | `DateTimeUTC (nullable)` | When ticket was closed |
| `resolved_at` | `DateTimeUTC (nullable)` | When ticket was resolved |
| `created_at` | `DateTimeUTC` | Auto |
| `updated_at` | `DateTimeUTC` | Auto |

**File**: `src/py/app/db/models/_ticket.py`

### `TicketMessage`

A message/reply within a ticket thread.

| Column | Type | Description |
|---|---|---|
| `id` | `UUIDv7` | Primary key |
| `ticket_id` | `UUIDv7 FK` | Parent ticket |
| `author_id` | `UUIDv7 FK` | Message author (user or agent) |
| `body_markdown` | `Text` | Message body in markdown |
| `body_html` | `Text` | Pre-rendered HTML (for display) |
| `is_internal_note` | `Boolean` | Internal note (visible to agents only) |
| `is_system_message` | `Boolean` | Auto-generated status change message |
| `created_at` | `DateTimeUTC` | Auto |
| `updated_at` | `DateTimeUTC` | Auto |

**File**: `src/py/app/db/models/_ticket_message.py`

### `TicketAttachment`

File attachments on ticket messages.

| Column | Type | Description |
|---|---|---|
| `id` | `UUIDv7` | Primary key |
| `ticket_message_id` | `UUIDv7 FK` | Parent message |
| `ticket_id` | `UUIDv7 FK` | Denormalized for efficient queries |
| `uploaded_by_id` | `UUIDv7 FK` | Who uploaded the file |
| `file_name` | `String(255)` | Original filename |
| `file_path` | `String(500)` | Storage path |
| `file_size_bytes` | `BigInteger` | File size |
| `content_type` | `String(100)` | MIME type (e.g., "image/png", "application/pdf") |
| `is_inline` | `Boolean` | Whether this is an inline image (embedded in markdown) |
| `created_at` | `DateTimeUTC` | Auto |

**File**: `src/py/app/db/models/_ticket_attachment.py`

---

## Backend Structure

```
src/py/app/domain/support/
├── __init__.py
├── controllers/
│   ├── __init__.py
│   ├── _ticket.py
│   ├── _ticket_message.py
│   └── _ticket_attachment.py
├── services/
│   ├── __init__.py
│   ├── _ticket.py
│   ├── _ticket_message.py
│   └── _ticket_attachment.py
├── schemas/
│   ├── __init__.py
│   ├── _ticket.py
│   ├── _ticket_message.py
│   └── _ticket_attachment.py
├── deps.py
├── guards.py
├── listeners.py
└── utils.py                         # Markdown rendering, ticket number generation
```

### Schemas

```python
# _ticket.py schemas
class Ticket(CamelizedBaseStruct):
    id: UUID
    ticket_number: str
    subject: str
    status: str
    priority: str
    category: str | None
    is_read_by_user: bool
    user: TicketUser          # Embedded: id, name, avatar
    assigned_to: TicketUser | None
    message_count: int
    latest_message_preview: str | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None

class TicketCreate(CamelizedBaseStruct):
    subject: str
    priority: str = "medium"
    category: str | None = None
    body_markdown: str        # Initial message body
    team_id: UUID | None = None

class TicketUpdate(CamelizedBaseStruct, omit_defaults=True):
    subject: str | UnsetType = UNSET
    status: str | UnsetType = UNSET
    priority: str | UnsetType = UNSET
    category: str | UnsetType = UNSET
    assigned_to_id: UUID | UnsetType | None = UNSET

# _ticket_message.py schemas
class TicketMessage(CamelizedBaseStruct):
    id: UUID
    author: TicketUser
    body_markdown: str
    body_html: str
    is_internal_note: bool
    is_system_message: bool
    attachments: list[TicketAttachment]
    created_at: datetime

class TicketMessageCreate(CamelizedBaseStruct):
    body_markdown: str
    is_internal_note: bool = False

# _ticket_attachment.py schemas
class TicketAttachment(CamelizedBaseStruct):
    id: UUID
    file_name: str
    file_size_bytes: int
    content_type: str
    is_inline: bool
    url: str                  # Pre-signed download URL
```

### API Endpoints

#### Tickets

| Method | Path | Operation | Description |
|---|---|---|---|
| `GET` | `/api/support/tickets` | `ListTickets` | List user's tickets (paginated, filterable) |
| `POST` | `/api/support/tickets` | `CreateTicket` | Open a new ticket |
| `GET` | `/api/support/tickets/{ticket_id}` | `GetTicket` | Get ticket details |
| `PATCH` | `/api/support/tickets/{ticket_id}` | `UpdateTicket` | Update ticket (status, priority, assign) |
| `POST` | `/api/support/tickets/{ticket_id}/close` | `CloseTicket` | Close a ticket |
| `POST` | `/api/support/tickets/{ticket_id}/reopen` | `ReopenTicket` | Reopen a closed ticket |

#### Ticket Messages

| Method | Path | Operation | Description |
|---|---|---|---|
| `GET` | `/api/support/tickets/{ticket_id}/messages` | `ListTicketMessages` | List messages in a ticket (paginated) |
| `POST` | `/api/support/tickets/{ticket_id}/messages` | `CreateTicketMessage` | Add a reply to a ticket |
| `PATCH` | `/api/support/tickets/{ticket_id}/messages/{msg_id}` | `UpdateTicketMessage` | Edit a message (own, within time window) |
| `DELETE` | `/api/support/tickets/{ticket_id}/messages/{msg_id}` | `DeleteTicketMessage` | Delete a message (own, within time window) |

#### Attachments

| Method | Path | Operation | Description |
|---|---|---|---|
| `POST` | `/api/support/tickets/{ticket_id}/attachments` | `UploadAttachment` | Upload file(s) for a ticket |
| `GET` | `/api/support/attachments/{attachment_id}` | `GetAttachment` | Download/view attachment |
| `DELETE` | `/api/support/attachments/{attachment_id}` | `DeleteAttachment` | Delete an attachment |
| `POST` | `/api/support/tickets/{ticket_id}/paste-image` | `PasteImage` | Upload a clipboard-pasted image |

### Guards

- `requires_ticket_access` — User is the ticket creator, assigned agent, or superuser.
- `requires_ticket_message_edit` — User is the message author and within the edit time window.
- `requires_support_agent` — User has support agent role (for internal notes, assignment).

### Service Logic

#### Ticket Number Generation
- Sequential format: `SUP-XXXXX` (zero-padded).
- Generated in `TicketService.to_model_on_create()`.
- Use a database sequence or atomic counter for uniqueness.

#### Markdown Rendering
- Server-side rendering of markdown to HTML for `body_html`.
- Use a safe markdown library (e.g., `markdown-it-py` or `mistune`) with sanitization.
- Support standard markdown: headings, bold, italic, code blocks, lists, links, tables.
- Support image embedding: `![alt](attachment-url)` syntax, linked to uploaded attachments.
- Sanitize HTML output to prevent XSS (strip script tags, event handlers, etc.).

#### Image Handling
- **Copy/Paste**: Frontend captures clipboard `paste` events, extracts image blobs, uploads via `PasteImage` endpoint, inserts markdown image reference into the editor.
- **File Attachment**: Standard file upload via `UploadAttachment`, returns attachment metadata for markdown insertion.
- **Inline vs. Attachment**: Images referenced in markdown body are marked `is_inline=True`. Other files are standard attachments listed below the message.
- **Storage**: Files stored on disk or object storage (configurable). Served via authenticated download endpoints.

#### Status Transitions

```
open → in_progress → resolved → closed
  ↑         ↑           ↓
  └─────────┴── reopen ←┘

  waiting_on_customer ⟷ waiting_on_support
```

- Status changes automatically create system messages in the thread.
- Closing a ticket sets `closed_at` timestamp.
- Reopening clears `closed_at` and `resolved_at`.

### Event Listeners

- `ticket_created` — Send confirmation email to user, notify support queue.
- `ticket_message_created` — Notify the other party (user or agent) via email.
- `ticket_status_changed` — Log audit event, send notification email.
- `ticket_assigned` — Notify the assigned agent.

---

## Frontend Structure

```
src/js/web/src/
├── routes/_app/support/
│   ├── index.tsx                       # Ticket list
│   ├── new.tsx                         # Create ticket form
│   └── $ticketId/
│       └── index.tsx                   # Ticket detail / conversation view
├── components/support/
│   ├── ticket-list.tsx                 # Ticket list with filters
│   ├── ticket-list-item.tsx            # Single ticket row
│   ├── ticket-status-badge.tsx         # Status pill/badge
│   ├── ticket-priority-badge.tsx       # Priority indicator
│   ├── ticket-detail-header.tsx        # Ticket metadata bar
│   ├── ticket-conversation.tsx         # Message thread
│   ├── ticket-message.tsx              # Single message bubble
│   ├── ticket-message-system.tsx       # System/status change message
│   ├── ticket-create-form.tsx          # New ticket form
│   ├── markdown-editor.tsx             # Rich markdown editor component
│   ├── markdown-renderer.tsx           # Safe markdown rendering
│   ├── image-paste-handler.tsx         # Clipboard image capture
│   ├── attachment-upload.tsx           # File upload with drag-and-drop
│   ├── attachment-list.tsx             # File attachment display
│   └── attachment-preview.tsx          # Image/PDF inline preview
└── lib/api/hooks/support.ts
```

### Pages

#### Ticket List (`/support`)
- Table of tickets with columns: number, subject, status, priority, category, last updated.
- **Filters**: status (open/closed/all), priority, category, date range.
- **Search**: Full-text search on subject and message content.
- Unread indicator for tickets with new replies.
- "New Ticket" button → `/support/new`.

#### Create Ticket (`/support/new`)
- **Form fields**:
  - Subject (text input).
  - Category (dropdown: billing, technical, account, device, voice, fax, general).
  - Priority (dropdown: low, medium, high, urgent — default: medium).
  - Body (markdown editor — see below).
  - Attachments (file upload area with drag-and-drop).
- On submit, creates ticket + initial message + attachments atomically.
- Redirects to ticket detail view.

#### Ticket Detail (`/support/:ticketId`)
- **Header**: Ticket number, subject, status badge, priority badge, category, assignee, created date.
- **Actions**: Close ticket, reopen ticket, change priority (dropdown).
- **Conversation thread**: Chronological list of messages.
  - User messages: aligned left or with user avatar.
  - Agent messages: aligned right or with agent avatar.
  - System messages: centered, muted styling.
  - Each message shows: author name, avatar, timestamp, rendered markdown body, attachments.
- **Reply composer** (bottom of page):
  - Markdown editor with toolbar.
  - Image paste support (Ctrl+V / Cmd+V).
  - File attachment button.
  - Submit button.

### Markdown Editor Component

The markdown editor is a critical component with these capabilities:

#### Features
- **Toolbar**: Bold, italic, heading, code (inline + block), link, image, list (ordered + unordered), quote, table.
- **Live preview**: Split-pane or toggle between edit and preview modes.
- **Keyboard shortcuts**: Ctrl+B (bold), Ctrl+I (italic), Ctrl+K (link), etc.
- **Image paste**: Intercept `paste` events on the editor. When clipboard contains an image:
  1. Extract the image blob from `clipboardData.items`.
  2. Upload to `/api/support/tickets/{id}/paste-image`.
  3. Receive back `{ id, url, fileName }`.
  4. Insert `![image](url)` at cursor position in the editor.
  5. Show upload progress indicator inline.
- **Image drag-and-drop**: Same flow as paste, triggered by `drop` events on the editor.
- **File attachment**: Separate from inline images. Button opens file picker, uploads to `/api/support/tickets/{id}/attachments`, shows in attachment list below editor.
- **Syntax highlighting**: Code blocks with language detection.

#### Implementation Approach
- Use an existing React markdown editor library (e.g., `@uiw/react-md-editor`, `react-markdown-editor-lite`, or build on top of `textarea` with `react-markdown` for preview).
- Rendering uses `react-markdown` with `remark-gfm` for GitHub-Flavored Markdown support.
- Sanitize rendered HTML with `rehype-sanitize` to prevent XSS.

### React Query Hooks

```typescript
// lib/api/hooks/support.ts
useTickets(filters)
useTicket(ticketId)
useCreateTicket()
useUpdateTicket(ticketId)
useCloseTicket(ticketId)
useReopenTicket(ticketId)

useTicketMessages(ticketId, pagination)
useCreateTicketMessage(ticketId)
useUpdateTicketMessage(ticketId, messageId)
useDeleteTicketMessage(ticketId, messageId)

useUploadAttachment(ticketId)
usePasteImage(ticketId)
useDeleteAttachment(attachmentId)
```

---

## Sub-Features & Tasks

### Phase 1: Ticket CRUD
- [ ] Create `Ticket`, `TicketMessage`, `TicketAttachment` database models
- [ ] Create Alembic migration
- [ ] Implement ticket number generation (sequential `SUP-XXXXX`)
- [ ] Implement `TicketService` with CRUD + status transitions
- [ ] Implement `TicketController` with REST endpoints
- [ ] Create all schemas (Ticket, TicketCreate, TicketUpdate, etc.)
- [ ] Add guards (ticket access, support agent role)
- [ ] Add dependency providers
- [ ] Regenerate TypeScript types

### Phase 2: Ticket Messages
- [ ] Implement `TicketMessageService` with CRUD
- [ ] Implement `TicketMessageController`
- [ ] Server-side markdown rendering to HTML (with sanitization)
- [ ] Implement auto-generated system messages on status changes
- [ ] Implement edit time window enforcement (e.g., 15 minutes)

### Phase 3: File Attachments & Image Handling
- [ ] Implement file upload service (shared or support-specific)
- [ ] Implement `TicketAttachmentService`
- [ ] Implement `UploadAttachment` endpoint (multipart form)
- [ ] Implement `PasteImage` endpoint (raw image blob)
- [ ] Implement authenticated download endpoint
- [ ] Configure file storage (local disk or object storage)
- [ ] Add file size limits and MIME type validation
- [ ] Add virus/malware scanning hook (optional, via SAQ)

### Phase 4: Frontend — Ticket List & Creation
- [ ] Build ticket list page with filters and search
- [ ] Build ticket status and priority badge components
- [ ] Build create ticket form with category and priority selection
- [ ] Integrate markdown editor for ticket body
- [ ] Implement file attachment upload in creation form

### Phase 5: Frontend — Ticket Detail & Conversation
- [ ] Build ticket detail header with metadata and actions
- [ ] Build conversation thread view
- [ ] Build message bubble component with markdown rendering
- [ ] Build system message component
- [ ] Build reply composer with markdown editor
- [ ] Implement image paste handler (clipboard interception)
- [ ] Implement image drag-and-drop handler
- [ ] Implement inline upload progress indicator
- [ ] Build attachment list and preview components
- [ ] Implement close/reopen actions
- [ ] Implement unread indicators and mark-as-read on view

### Phase 6: Notifications
- [ ] Implement `ticket_created` event listener + email
- [ ] Implement `ticket_message_created` event listener + email
- [ ] Implement `ticket_status_changed` event listener + email
- [ ] Implement `ticket_assigned` event listener + email
- [ ] Create React Email templates for all ticket notifications

### Phase 7: Admin / Agent Views
- [ ] Add `/admin/support` dashboard with queue overview
- [ ] Add ticket assignment interface for agents
- [ ] Add internal notes capability (visible to agents only)
- [ ] Add bulk actions (close multiple, reassign)
- [ ] Add support metrics (response time, resolution time, volume)
- [ ] Add audit log entries for ticket operations
