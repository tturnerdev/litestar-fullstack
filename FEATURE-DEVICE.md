# Feature: Device Management

## Summary

The Device feature area provides users with controls to view, configure, and monitor physical and virtual devices associated with their account. This includes desk phones, softphones, ATAs (Analog Telephone Adapters), and other SIP-capable hardware.

---

## Domain Module

**Backend**: `src/py/app/domain/devices/`
**Frontend**: `src/js/web/src/routes/_app/devices/` + `src/js/web/src/components/devices/`

---

## Database Models

### `Device`

| Column | Type | Description |
|---|---|---|
| `id` | `UUIDv7` | Primary key (from `UUIDv7AuditBase`) |
| `user_id` | `UUIDv7 FK` | Owner of the device (`user_account.id`) |
| `team_id` | `UUIDv7 FK (nullable)` | Team the device is assigned to (optional) |
| `name` | `String(255)` | User-friendly device name (e.g., "Desk Phone - Office") |
| `device_type` | `Enum` | `desk_phone`, `softphone`, `ata`, `conference`, `other` |
| `mac_address` | `String(17) (nullable)` | MAC address for physical devices |
| `model` | `String(100) (nullable)` | Device model (e.g., "Polycom VVX 450") |
| `manufacturer` | `String(100) (nullable)` | Device manufacturer |
| `firmware_version` | `String(50) (nullable)` | Current firmware version |
| `ip_address` | `String(45) (nullable)` | Last known IP (v4 or v6) |
| `sip_username` | `String(100)` | SIP registration username |
| `sip_server` | `String(255)` | SIP server address |
| `status` | `Enum` | `online`, `offline`, `ringing`, `in_use`, `error` |
| `is_active` | `Boolean` | Whether device is enabled |
| `last_seen_at` | `DateTimeUTC (nullable)` | Last registration/heartbeat timestamp |
| `provisioned_at` | `DateTimeUTC (nullable)` | When device was first provisioned |
| `config_json` | `JSON (nullable)` | Device-specific configuration blob |
| `created_at` | `DateTimeUTC` | Auto (from base) |
| `updated_at` | `DateTimeUTC` | Auto (from base) |

**File**: `src/py/app/db/models/_device.py`

### `DeviceLineAssignment`

Maps extensions/lines to device line keys.

| Column | Type | Description |
|---|---|---|
| `id` | `UUIDv7` | Primary key |
| `device_id` | `UUIDv7 FK` | The device |
| `line_number` | `Integer` | Line key position (1, 2, 3...) |
| `extension_id` | `UUIDv7 FK (nullable)` | Linked voice extension (from Voice domain) |
| `label` | `String(50)` | Display label on device |
| `line_type` | `Enum` | `private`, `shared`, `monitored` |
| `is_active` | `Boolean` | Whether this line is enabled |

**File**: `src/py/app/db/models/_device_line_assignment.py`

---

## Backend Structure

```
src/py/app/domain/devices/
├── __init__.py
├── controllers/
│   ├── __init__.py
│   └── _device.py
├── services/
│   ├── __init__.py
│   └── _device.py
├── schemas/
│   ├── __init__.py
│   └── _device.py
├── deps.py
├── guards.py
└── listeners.py
```

### Schemas

```python
# _device.py schemas
class Device(CamelizedBaseStruct):
    """Full device representation."""
    id: UUID
    name: str
    device_type: str
    mac_address: str | None
    model: str | None
    manufacturer: str | None
    firmware_version: str | None
    ip_address: str | None
    sip_username: str
    status: str
    is_active: bool
    last_seen_at: datetime | None
    provisioned_at: datetime | None
    lines: list[DeviceLineAssignment]

class DeviceCreate(CamelizedBaseStruct):
    name: str
    device_type: str
    mac_address: str | None = None
    model: str | None = None
    manufacturer: str | None = None
    sip_username: str | None = None   # auto-generate if not provided
    team_id: UUID | None = None

class DeviceUpdate(CamelizedBaseStruct, omit_defaults=True):
    name: str | UnsetType = UNSET
    is_active: bool | UnsetType = UNSET
    mac_address: str | UnsetType | None = UNSET
    model: str | UnsetType | None = UNSET
    config_json: dict | UnsetType | None = UNSET
```

### API Endpoints

| Method | Path | Operation | Description |
|---|---|---|---|
| `GET` | `/api/devices` | `ListDevices` | List user's devices (paginated, filterable) |
| `POST` | `/api/devices` | `CreateDevice` | Register a new device |
| `GET` | `/api/devices/{device_id}` | `GetDevice` | Get device details |
| `PATCH` | `/api/devices/{device_id}` | `UpdateDevice` | Update device settings |
| `DELETE` | `/api/devices/{device_id}` | `DeleteDevice` | Decommission / remove device |
| `POST` | `/api/devices/{device_id}/reboot` | `RebootDevice` | Send reboot command |
| `POST` | `/api/devices/{device_id}/reprovision` | `ReprovisionDevice` | Trigger reprovisioning |
| `GET` | `/api/devices/{device_id}/lines` | `ListDeviceLines` | Get line assignments |
| `PUT` | `/api/devices/{device_id}/lines` | `SetDeviceLines` | Bulk set line assignments |

### Guards

- `requires_device_ownership` — User owns the device or is superuser.
- `requires_device_team_access` — User is a member of the team the device belongs to.

### Service Logic

- **Auto-provisioning**: On create, generate SIP credentials and queue a provisioning task via SAQ.
- **Status sync**: Background task to poll/update device registration status.
- **Reboot/Reprovision**: Dispatch commands via SIP NOTIFY or provisioning API; queue as SAQ tasks.

### Event Listeners

- `device_created` — Log audit event, trigger initial provisioning.
- `device_offline` — (Future) Send alert notification if device goes offline.

---

## Frontend Structure

```
src/js/web/src/
├── routes/_app/devices/
│   ├── index.tsx                   # Device list page
│   ├── new.tsx                     # Add device form
│   └── $deviceId/
│       └── index.tsx               # Device detail / settings page
├── components/devices/
│   ├── device-list.tsx             # Device list with search/filter
│   ├── device-card.tsx             # Individual device card
│   ├── device-status-badge.tsx     # Online/offline/error indicator
│   ├── device-form.tsx             # Create/edit device form
│   ├── device-line-config.tsx      # Line assignment editor
│   └── device-actions.tsx          # Reboot, reprovision buttons
└── lib/api/hooks/devices.ts        # React Query hooks
```

### Pages

#### Device List (`/devices`)
- Grid or table of devices with status indicators.
- Search by name, filter by type and status.
- Quick actions: reboot, enable/disable.
- "Add Device" button → `/devices/new`.

#### Add Device (`/devices/new`)
- Form: name, type, MAC address, model selection.
- Optional: assign to team.
- On submit, device is provisioned and user is redirected to detail view.

#### Device Detail (`/devices/:deviceId`)
- **Overview tab**: Name, type, model, MAC, IP, firmware, status, last seen.
- **Lines tab**: Line key assignments (drag-and-drop reorder).
- **Settings tab**: SIP configuration, config JSON editor (advanced).
- **Actions**: Reboot, reprovision, deactivate, delete.

### React Query Hooks

```typescript
// lib/api/hooks/devices.ts
useDevices(filters)         // GET /api/devices
useDevice(deviceId)         // GET /api/devices/:id
useCreateDevice()           // POST /api/devices
useUpdateDevice(deviceId)   // PATCH /api/devices/:id
useDeleteDevice(deviceId)   // DELETE /api/devices/:id
useRebootDevice(deviceId)   // POST /api/devices/:id/reboot
useReprovisionDevice(id)    // POST /api/devices/:id/reprovision
useDeviceLines(deviceId)    // GET /api/devices/:id/lines
useSetDeviceLines(deviceId) // PUT /api/devices/:id/lines
```

---

## Sub-Features & Tasks

### Phase 1: Core CRUD
- [ ] Create `Device` and `DeviceLineAssignment` database models
- [ ] Create Alembic migration
- [ ] Implement `DeviceService` with standard CRUD
- [ ] Implement `DeviceController` with REST endpoints
- [ ] Create schemas (Device, DeviceCreate, DeviceUpdate)
- [ ] Add guards (ownership, team access)
- [ ] Add dependency providers
- [ ] Regenerate TypeScript types (`make types`)
- [ ] Build device list page with search/filter
- [ ] Build add device form
- [ ] Build device detail page

### Phase 2: Device Actions
- [ ] Implement reboot endpoint + SAQ background task
- [ ] Implement reprovision endpoint + SAQ background task
- [ ] Add action buttons to device detail UI
- [ ] Add confirmation dialogs for destructive actions

### Phase 3: Line Configuration
- [ ] Implement line assignment endpoints
- [ ] Build line configuration UI component
- [ ] Integrate with Voice domain extensions (cross-domain dependency)

### Phase 4: Status Monitoring
- [ ] Implement background status polling task (SAQ)
- [ ] Add real-time status updates (polling or WebSocket)
- [ ] Add device status dashboard widget
- [ ] Implement `device_offline` event listener + notifications

### Phase 5: Admin Views
- [ ] Add `/admin/devices` management page
- [ ] Add bulk operations (reboot all, export list)
- [ ] Add device audit log entries
