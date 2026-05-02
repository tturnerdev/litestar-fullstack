# Feature: Cross-Domain Entity Linking

## Summary

The Integration feature establishes navigable relationships between entities across domains. Today, most domain models exist in isolation: a Device has no FK to its physical Location, an Extension has no link to its E911 profile, and Connections have no way to declare which Devices or Extensions they manage. This feature closes those gaps with foreign keys, junction tables, schema enrichments, and bidirectional UI navigation so that any entity's related context is visible from its detail page.

---

## Current State of Cross-Domain Links

Before adding new links, here is what already exists in the database:

| Link | Mechanism | Status |
|---|---|---|
| Device → User | `device.user_id` FK | **Exists** |
| Device → Team | `device.team_id` FK | **Exists** |
| DeviceLineAssignment → Device | `device_line_assignment.device_id` FK | **Exists** |
| DeviceLineAssignment → Extension | `device_line_assignment.extension_id` (bare UUID, no FK constraint) | **Partial** — column exists but lacks a formal FK to `extension.id` |
| Extension → User | `extension.user_id` FK | **Exists** |
| Extension → PhoneNumber | `extension.phone_number_id` FK | **Exists** |
| PhoneNumber → User | `phone_number.user_id` FK | **Exists** |
| PhoneNumber → Team | `phone_number.team_id` FK | **Exists** |
| E911Registration → PhoneNumber | `e911_registration.phone_number_id` FK | **Exists** |
| E911Registration → Location | `e911_registration.location_id` FK | **Exists** |
| E911Registration → Team | `e911_registration.team_id` FK | **Exists** |
| RingGroupMember → Extension | `ring_group_member.extension_id` FK | **Exists** |
| CallQueueMember → Extension | `call_queue_member.extension_id` FK | **Exists** |
| TimeCondition → Schedule | `time_condition.schedule_id` FK | **Exists** |
| FaxNumber → User | `fax_number.user_id` FK | **Exists** |
| FaxNumber → Team | `fax_number.team_id` FK | **Exists** |
| Ticket → User | `ticket.user_id` FK | **Exists** |
| Ticket → Team | `ticket.team_id` FK | **Exists** |

---

## Required Links (Known Dependencies)

These links address real operational needs and are confirmed as required.

### Link 1: Device ↔ Location

A device sits at a physical location. Knowing the location enables E911 compliance, inventory tracking, and site-level device views.

| Attribute | Value |
|---|---|
| Mechanism | `location_id` FK on `device` table |
| Constraint | `FOREIGN KEY (location_id) REFERENCES location(id) ON DELETE SET NULL` |
| Nullable | Yes — devices may be unassigned or mobile |
| Direction | Device → Location (FK), Location → Devices (reverse relationship) |

**Model change** (`_device.py`):

```python
location_id: Mapped[UUID | None] = mapped_column(
    ForeignKey("location.id", ondelete="set null"),
    nullable=True,
    default=None,
    index=True,
)

location: Mapped[Location | None] = relationship(
    foreign_keys="Device.location_id",
    uselist=False,
    lazy="joined",
)
```

**Schema changes**:
- `Device` schema: add `location_id: UUID | None = None` and `location_name: str | None = None`
- `DeviceCreate` schema: add `location_id: UUID | None = None`
- `DeviceUpdate` schema: add `location_id: UUID | msgspec.UnsetType | None = msgspec.UNSET`
- `Location` schema: add `device_count: int = 0` (computed in service, not stored)

**UI changes**:
- Device detail page: show location name as a clickable link to `/locations/:locationId`
- Device create/edit form: add Location dropdown (filtered by team)
- Location detail page: add "Devices at this location" section with a table of linked devices

### Link 2: DeviceLineAssignment ↔ Extension (formalize FK)

The `extension_id` column on `device_line_assignment` already exists but lacks a foreign key constraint. This must be formalized for referential integrity and to enable ORM relationship loading.

| Attribute | Value |
|---|---|
| Mechanism | Add FK constraint on existing `device_line_assignment.extension_id` column |
| Constraint | `FOREIGN KEY (extension_id) REFERENCES extension(id) ON DELETE SET NULL` |
| Nullable | Yes — a line key can be unassigned |
| Direction | DeviceLineAssignment → Extension (FK), Extension → DeviceLineAssignments (reverse) |

**Model change** (`_device_line_assignment.py`):

```python
extension_id: Mapped[UUID | None] = mapped_column(
    ForeignKey("extension.id", ondelete="set null"),
    nullable=True,
    default=None,
    index=True,
)

extension: Mapped[Extension | None] = relationship(
    foreign_keys="DeviceLineAssignment.extension_id",
    uselist=False,
    lazy="joined",
)
```

**Model change** (`_extension.py`) — add reverse relationship:

```python
device_line_assignments: Mapped[list[DeviceLineAssignment]] = relationship(
    foreign_keys="DeviceLineAssignment.extension_id",
    uselist=True,
    lazy="noload",
    viewonly=True,
)
```

**Schema changes**:
- `DeviceLineAssignment` schema: add `extension_number: str | None = None` and `extension_display_name: str | None = None`
- Extension detail response: add `assigned_devices: list[DeviceLineAssignmentSummary]` (device name, line number, line type)

**UI changes**:
- Device line configuration: show extension number/name next to each line assignment
- Extension detail page: add "Assigned to Devices" section listing which devices have this extension on a line key

### Link 3: Extension ↔ E911 Registration

An extension's E911 profile determines where emergency calls from that extension are routed. This is derived through the extension's assigned phone number: `Extension → PhoneNumber → E911Registration`. No new FK is needed, but the chain must be surfaced in schemas and UI.

| Attribute | Value |
|---|---|
| Mechanism | Derived join: `extension.phone_number_id → phone_number.id → e911_registration.phone_number_id` |
| New FK | None required — the chain already exists |
| Direction | Read-only traversal in schemas and UI |

**Schema changes**:
- Extension detail response: add `e911_status` computed field:
  ```python
  e911_status: str | None = None          # "registered" | "unregistered" | None
  e911_registration_id: UUID | None = None
  e911_address_summary: str | None = None  # e.g. "123 Main St, Dallas TX 75201"
  ```

**Service changes**:
- `ExtensionService.get()`: when loading extension details, join through `phone_number → e911_registration` to populate the E911 fields
- Add a warning flag if an extension has a phone number but no E911 registration

**UI changes**:
- Extension detail page: add E911 status badge ("Registered" / "Not Registered")
- If registered, show address summary as a link to `/e911/:registrationId`
- If not registered, show a warning banner with a link to create a registration

### Link 4: Phone Number ↔ E911 Registration (enforcement)

Every phone number with active call service should have an E911 registration. The FK already exists on `e911_registration.phone_number_id`. This link adds enforcement, validation, and UI surfacing.

| Attribute | Value |
|---|---|
| Mechanism | Existing FK: `e911_registration.phone_number_id → phone_number.id` |
| New FK | None — already exists |
| Direction | PhoneNumber → E911Registration (reverse lookup) |

**Model change** (`_phone_number.py`) — add reverse relationship:

```python
e911_registration: Mapped[E911Registration | None] = relationship(
    foreign_keys="E911Registration.phone_number_id",
    uselist=False,
    lazy="noload",
    viewonly=True,
)
```

**Schema changes**:
- `PhoneNumber` detail response: add `e911_registered: bool = False` and `e911_registration_id: UUID | None = None`
- Phone number list response: include `e911_registered` boolean for badge display

**Service changes**:
- `PhoneNumberService`: add method `get_unregistered_numbers(team_id)` for compliance dashboards
- Emit `phone_number_e911_missing` event on phone number creation (deferred check after 24h via SAQ)

**UI changes**:
- Phone numbers list: add E911 status badge per row
- Phone number detail: show E911 registration status; link to registration if exists, or prompt to create one
- E911 list page: add "Unregistered Numbers" count badge in page header

### Link 5: Device ↔ Connection

A Connection of type `pbx` manages devices through its provisioning/SIP interface. Linking a device to its managing connection enables per-connection device views and connection health impact analysis.

| Attribute | Value |
|---|---|
| Mechanism | `connection_id` FK on `device` table |
| Constraint | `FOREIGN KEY (connection_id) REFERENCES connection(id) ON DELETE SET NULL` |
| Nullable | Yes — standalone/unmanaged devices have no connection |
| Direction | Device → Connection (FK), Connection → Devices (reverse) |

**Model change** (`_device.py`):

```python
connection_id: Mapped[UUID | None] = mapped_column(
    ForeignKey("connection.id", ondelete="set null"),
    nullable=True,
    default=None,
    index=True,
)

connection: Mapped[Connection | None] = relationship(
    foreign_keys="Device.connection_id",
    uselist=False,
    lazy="joined",
)
```

**Schema changes**:
- `Device` schema: add `connection_id: UUID | None = None` and `connection_name: str | None = None`
- `DeviceCreate` schema: add `connection_id: UUID | None = None`
- `DeviceUpdate` schema: add `connection_id: UUID | msgspec.UnsetType | None = msgspec.UNSET`

**UI changes**:
- Device detail page: show connection name as a link to `/connections/:connectionId`
- Device create/edit form: add Connection dropdown (filtered by team, type=`pbx`)
- Connection detail page: add "Managed Devices" section

---

## Candidate Links (Suggested -- Needs User Confirmation)

These links are architecturally sound but may not be needed yet. Each is flagged for review before implementation.

### Candidate A: Connection ↔ Extension

Track which PBX connection owns/manages each extension.

| Attribute | Value |
|---|---|
| Mechanism | `connection_id` FK on `extension` table |
| Constraint | `FOREIGN KEY (connection_id) REFERENCES connection(id) ON DELETE SET NULL` |
| Nullable | Yes |
| Rationale | Enables per-connection extension views; when a connection goes down, immediately identify affected extensions |
| Risk | Extensions currently have no team_id — scoping through connection.team_id adds implicit team ownership |

**Open questions**:
- Should `Extension` also get a `team_id` FK for consistency with Device, PhoneNumber, etc.?
- Or is the connection link sufficient to infer team scope?

### Candidate B: Fax Number ↔ Location

Associate a fax number with the physical location where the fax machine or ATA resides.

| Attribute | Value |
|---|---|
| Mechanism | `location_id` FK on `fax_number` table |
| Constraint | `FOREIGN KEY (location_id) REFERENCES location(id) ON DELETE SET NULL` |
| Nullable | Yes |
| Rationale | Enables location-level fax inventory; useful for multi-site organizations |
| Risk | Low — simple nullable FK. Many fax numbers may be virtual (email-to-fax) with no physical location |

### Candidate C: Schedule ↔ Extension

Apply a business-hours schedule to an extension to control call routing behavior (ring during business hours, forward to voicemail after hours).

| Attribute | Value |
|---|---|
| Mechanism | `schedule_id` FK on `extension` table |
| Constraint | `FOREIGN KEY (schedule_id) REFERENCES schedule(id) ON DELETE SET NULL` |
| Nullable | Yes |
| Rationale | TimeCondition already links Schedule to call routing, but this gives a direct per-extension schedule assignment for simpler use cases |
| Risk | May overlap with the existing TimeCondition model — need to decide if this is a convenience shortcut or a replacement |

**Open questions**:
- Is this redundant with TimeCondition-based routing?
- Should the Extension → Schedule link be the primary mechanism, with TimeCondition reserved for complex multi-branch routing?

### Candidate D: Ticket ↔ Device / Extension

Link a support ticket to the specific device or extension it concerns.

| Attribute | Value |
|---|---|
| Mechanism | Optional `device_id` and `extension_id` FKs on `ticket` table |
| Constraint | Both nullable, both `ON DELETE SET NULL` |
| Rationale | Enables support staff to see full device/extension context; enables device detail pages to show open tickets |
| Risk | The `ticket.category` enum already has `device` and `voice` values — this adds structured FK references vs. free-text categorization |

**Open questions**:
- Should this be two separate FKs, or a polymorphic `related_entity_type` + `related_entity_id` pattern?
- How many tickets are actually about a specific device vs. general account issues?

### Candidate E: Extension ↔ Team

Add a `team_id` FK to `Extension` for consistency with other team-scoped entities.

| Attribute | Value |
|---|---|
| Mechanism | `team_id` FK on `extension` table |
| Constraint | `FOREIGN KEY (team_id) REFERENCES team(id) ON DELETE SET NULL` |
| Nullable | Yes |
| Rationale | Device, PhoneNumber, FaxNumber, E911Registration, Schedule, Connection, Location all have team_id. Extension is a notable outlier, relying only on user_id for scoping |
| Risk | Requires backfill for existing extensions; needs logic to keep team_id in sync when user team membership changes |

---

## Database Migrations

All schema changes are consolidated into phased migrations. Each phase produces a single Alembic migration file.

### Migration Strategy

- Each phase creates one migration with `op.add_column`, `op.create_foreign_key`, and `op.create_index` operations
- Downgrade operations drop the FK, index, and column in reverse order
- Link 2 (DeviceLineAssignment FK formalization) uses `op.create_foreign_key` on the existing column without adding a new column

---

## Backend Structure

This feature does **not** introduce a new domain module. Changes are distributed across existing domains:

```
src/py/app/domain/
├── devices/
│   ├── schemas/_device.py          # Add location_id, connection_id, location_name, connection_name
│   ├── services/_device.py         # Eager-load location and connection relationships
│   └── controllers/_device.py      # No endpoint changes (existing CRUD covers new fields)
├── voice/
│   ├── schemas/_extension.py       # Add e911_status fields, assigned_devices summary
│   ├── schemas/_phone_number.py    # Add e911_registered, e911_registration_id
│   └── services/_extension.py      # Join through phone_number → e911_registration
│   └── services/_phone_number.py   # Add get_unregistered_numbers method
├── e911/
│   ├── schemas/_e911_registration.py  # Already has phone_number_display, location_name (no changes)
│   └── controllers/_e911_registration.py  # No changes
├── locations/
│   ├── schemas/_location.py        # Add device_count
│   └── services/_location.py       # Compute device_count via query
└── connections/
    ├── schemas/_connection.py      # Add managed_device_count
    └── services/_connection.py     # Compute managed_device_count via query
```

### API Endpoint Changes

No new endpoints are required. Existing CRUD endpoints absorb the new fields through schema updates:

| Endpoint | Change |
|---|---|
| `GET /api/devices/:id` | Response includes `locationId`, `locationName`, `connectionId`, `connectionName` |
| `POST /api/devices` | Request accepts `locationId`, `connectionId` |
| `PATCH /api/devices/:id` | Request accepts `locationId`, `connectionId` |
| `GET /api/devices/:id/lines` | Line items include `extensionNumber`, `extensionDisplayName` |
| `GET /api/voice/extensions/:id` | Response includes `e911Status`, `e911RegistrationId`, `e911AddressSummary`, `assignedDevices` |
| `GET /api/voice/phone-numbers` | Response items include `e911Registered` |
| `GET /api/voice/phone-numbers/:id` | Response includes `e911Registered`, `e911RegistrationId` |
| `GET /api/locations/:id` | Response includes `deviceCount` |
| `GET /api/connections/:id` | Response includes `managedDeviceCount` |

### New API Endpoint (Optional)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/voice/phone-numbers/unregistered-e911` | List phone numbers without E911 registrations (for compliance dashboard) |

---

## Frontend Structure

### UI Component Changes (Existing Pages)

#### Device Detail (`/devices/:deviceId`)
- Add "Location" field in overview section: location name as a link, or "Not assigned" with an "Assign" button
- Add "Connection" field: connection name as a link, or "Unmanaged"
- Line configuration: show extension number and display name next to each assigned line

#### Device Create/Edit Form
- Add Location select dropdown (searchable, filtered by team)
- Add Connection select dropdown (filtered by team, connection_type = `pbx`)

#### Extension Detail (`/voice/extensions/:extensionId`)
- Add "E911 Status" section:
  - Green badge + address summary + link if registered
  - Yellow warning banner + "Register" action if unregistered
- Add "Assigned to Devices" section: table of devices with this extension on a line key (device name, line number, line type, link to device)

#### Phone Number List (`/voice/phone-numbers`)
- Add E911 badge per row: green check or yellow warning icon

#### Phone Number Detail (`/voice/phone-numbers/:id`)
- Add E911 status section (same pattern as extension detail)

#### Location Detail (`/locations/:locationId`)
- Add "Devices" section: table of devices assigned to this location (name, type, status, link to device)

#### Connection Detail (`/connections/:connectionId`)
- Add "Managed Devices" section: table of devices linked to this connection (name, type, status, link to device)

### New Shared Components

```
src/js/web/src/components/shared/
├── entity-link-badge.tsx         # Reusable badge showing linked entity with navigation
├── e911-status-badge.tsx         # Green/yellow badge for E911 registration status
└── related-entities-section.tsx  # Collapsible section for showing related entities on detail pages
```

### React Query Hook Changes

No new hook files. Existing hooks return the enriched schemas automatically after `make types` regenerates the TypeScript client.

---

## Sub-Features & Tasks

### Phase 1: Device ↔ Location

- [x] Add `location_id` FK column to `Device` model (`_device.py`)
- [x] Add `Location` relationship to `Device` model
- [ ] Add reverse `devices` relationship to `Location` model (`_location.py`)
- [x] Create Alembic migration (add column, FK constraint, index)
- [x] Update `Device` schema: add `location_id`, `location_name`
- [x] Update `DeviceCreate` schema: add `location_id`
- [x] Update `DeviceUpdate` schema: add `location_id`
- [ ] Update `Location` schema: add `device_count`
- [x] Update `DeviceService` to eager-load location relationship
- [ ] Update `LocationService` to compute `device_count`
- [x] Regenerate TypeScript types (`make types`)
- [x] Add Location field to device detail page overview section — shows as clickable link
- [x] Add Location dropdown to device create/edit form — Select dropdown with location options
- [x] Add "Devices at this location" section to location detail page
- [ ] Build `RelatedEntitiesSection` shared component

### Phase 2: DeviceLineAssignment ↔ Extension (FK formalization)

- [x] Add FK constraint on `device_line_assignment.extension_id` → `extension.id`
- [x] Add `Extension` relationship to `DeviceLineAssignment` model
- [x] Add reverse `device_line_assignments` relationship to `Extension` model
- [x] Create Alembic migration (add FK constraint and index on existing column)
- [x] Update `DeviceLineAssignment` schema: add `extension_number`, `extension_display_name`
- [ ] Create `DeviceLineAssignmentSummary` schema for extension detail response
- [x] Update `DeviceService` line loading to eager-load extension
- [ ] Update `ExtensionService` to support loading assigned devices
- [x] Regenerate TypeScript types (`make types`) — done in v0.155.0
- [x] Show extension number/name in device line configuration UI
- [x] Add "Assigned to Devices" section to extension detail page

### Phase 3: Extension ↔ E911 and Phone Number ↔ E911 (surfacing)

- [x] Add reverse `e911_registration` relationship to `PhoneNumber` model
- [ ] Update Extension detail schema: add `e911_status`, `e911_registration_id`, `e911_address_summary`
- [x] Update PhoneNumber list schema: add `e911_registered`
- [x] Update PhoneNumber detail schema: add `e911_registered`, `e911_registration_id`
- [ ] Update `ExtensionService.get()` to join `phone_number → e911_registration`
- [x] Update `PhoneNumberService` to check E911 status on detail/list queries
- [x] Add `get_unregistered_numbers(team_id)` method to `PhoneNumberService`
- [x] Add `GET /api/voice/phone-numbers/unregistered-e911` endpoint
- [x] Regenerate TypeScript types (`make types`)
- [x] Build `E911StatusBadge` shared component — created at `src/js/web/src/components/voice/e911-status-badge.tsx`
- [x] Add E911 status section to extension detail page — added via `usePhoneNumber` hook, shows Shield/ShieldOff icons with registration link
- [x] Add E911 badge to phone number list rows — added E911 column with E911StatusBadge
- [x] Add E911 status section to phone number detail page — added with "View Registration" link
- [x] Add "Unregistered Numbers" count to E911 list page header

### Phase 4: Device ↔ Connection

- [x] Add `connection_id` FK column to `Device` model (`_device.py`)
- [x] Add `Connection` relationship to `Device` model
- [ ] Add reverse `devices` relationship to `Connection` model (`_connection.py`)
- [x] Create Alembic migration (add column, FK constraint, index)
- [x] Update `Device` schema: add `connection_id`, `connection_name`
- [x] Update `DeviceCreate` schema: add `connection_id`
- [x] Update `DeviceUpdate` schema: add `connection_id`
- [ ] Update `Connection` schema: add `managed_device_count`
- [x] Update `DeviceService` to eager-load connection relationship
- [ ] Update `ConnectionService` to compute `managed_device_count`
- [x] Regenerate TypeScript types (`make types`)
- [x] Add Connection field to device detail page — shows as clickable link
- [x] Add Connection dropdown to device create/edit form — Select dropdown
- [x] Add "Managed Devices" section to connection detail page

### Phase 5: Review Candidate Links

- [ ] Review Candidate A (Connection ↔ Extension) with user — decide on team scoping approach
- [ ] Review Candidate B (FaxNumber ↔ Location) with user — assess need based on deployment patterns
- [ ] Review Candidate C (Schedule ↔ Extension) with user — resolve overlap with TimeCondition
- [ ] Review Candidate D (Ticket ↔ Device/Extension) with user — decide FK vs. polymorphic approach
- [ ] Review Candidate E (Extension ↔ Team) with user — plan backfill strategy
- [ ] Implement approved candidate links following the same pattern as Phases 1-4

---

## Testing Considerations

- **Migration safety**: Test that FK additions do not fail on existing data where referenced IDs may not exist (all new FKs are nullable with `ON DELETE SET NULL`)
- **Relationship loading**: Verify that eager-loaded relationships do not cause N+1 queries on list endpoints
- **Cross-team isolation**: Ensure a device cannot be linked to a location belonging to a different team
- **Cascade behavior**: Verify `ON DELETE SET NULL` correctly nullifies FKs when a location or connection is deleted
- **Schema backward compatibility**: Confirm that API consumers handle the new nullable fields gracefully (all additions have defaults)

---

## Dependencies & Ordering

```
Phase 1 (Device ↔ Location)
    └── No dependencies — can start immediately

Phase 2 (DeviceLineAssignment ↔ Extension FK)
    └── No dependencies — can start immediately (can parallel with Phase 1)

Phase 3 (E911 surfacing)
    └── Depends on: Phase 2 (extension detail page additions)

Phase 4 (Device ↔ Connection)
    └── Depends on: Phase 1 (device model already modified — migration ordering)

Phase 5 (Candidate Links)
    └── Depends on: Phases 1-4 complete; user review of candidates
```

Phases 1 and 2 can be implemented in parallel. Phase 3 should follow Phase 2 since both modify the extension detail page. Phase 4 should follow Phase 1 since both modify the Device model and need coordinated migrations.
