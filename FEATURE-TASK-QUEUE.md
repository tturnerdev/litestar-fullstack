# Feature: Background Task Queue Tracking

## Summary

The Task Queue feature provides a persistent tracking layer on top of SAQ (Simple Async Queue) so that users and administrators can observe the lifecycle of background operations. When a controller enqueues a long-running job (device reboot, fax send, extension provisioning), a `BackgroundTask` row is created in PostgreSQL and updated as the SAQ job progresses. The frontend surfaces task state through a dedicated list page, an active-task indicator in the header, and toast notifications on completion or failure.

This feature does **not** replace SAQ. SAQ remains the execution engine; `BackgroundTask` is the observability and audit record.

---

## Domain Module

**Backend**: `src/py/app/domain/tasks/`
**Frontend**: `src/js/web/src/routes/_app/tasks/` + `src/js/web/src/components/tasks/`

---

## Database Models

### `BackgroundTaskStatus` (Enum)

Stored in `src/py/app/db/models/_background_task_status.py`.

| Value | Description |
|---|---|
| `pending` | Task record created, SAQ job enqueued but not yet picked up |
| `running` | SAQ worker has started executing the job |
| `completed` | Job finished successfully |
| `failed` | Job raised an unhandled exception or explicitly reported failure |
| `cancelled` | User or system cancelled the task before completion |

```python
import enum

class BackgroundTaskStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
```

### `BackgroundTask`

Persistent record of a background job and its lifecycle.

| Column | Type | Description |
|---|---|---|
| `id` | `UUIDv7` | Primary key (from `UUIDv7AuditBase`) |
| `task_type` | `String(50)` | Dot-delimited type identifier (e.g., `device.reboot`, `fax.send`) |
| `status` | `Enum(BackgroundTaskStatus)` | Current lifecycle state |
| `progress` | `Integer` | Percentage complete, 0-100 (default 0) |
| `entity_type` | `String(50) (nullable)` | Type of related domain entity (e.g., `device`, `fax_message`, `extension`) |
| `entity_id` | `UUID (nullable)` | ID of the related domain entity |
| `team_id` | `UUID FK` | Team context (`team.id`, ondelete CASCADE) |
| `initiated_by_id` | `UUID FK` | User who triggered the task (`user_account.id`, ondelete SET NULL, nullable) |
| `payload` | `JSONB (nullable)` | Input parameters passed to the SAQ job |
| `result` | `JSONB (nullable)` | Output data on success |
| `error_message` | `Text (nullable)` | Error details on failure |
| `saq_job_key` | `String(100) (nullable)` | SAQ job key for correlation with the Redis-backed queue |
| `started_at` | `DateTimeUTC (nullable)` | When the SAQ worker began execution |
| `completed_at` | `DateTimeUTC (nullable)` | When execution finished (success or failure) |
| `created_at` | `DateTimeUTC` | Auto (from `UUIDv7AuditBase`) |
| `updated_at` | `DateTimeUTC` | Auto (from `UUIDv7AuditBase`) |

**File**: `src/py/app/db/models/_background_task.py`

#### Indexes

- `ix_background_task_status` on `status` (filter active tasks)
- `ix_background_task_task_type` on `task_type` (filter by operation kind)
- `ix_background_task_team_id` on `team_id` (team-scoped queries)
- `ix_background_task_initiated_by_id` on `initiated_by_id` (user's own tasks)
- `ix_background_task_entity` composite on `(entity_type, entity_id)` (find tasks for an entity)

#### Relationships

- `team` -> `Team` (many-to-one, lazy="noload")
- `initiated_by` -> `User` (many-to-one, lazy="joined")

---

## Backend Structure

```
src/py/app/domain/tasks/
├── __init__.py
├── controllers/
│   ├── __init__.py
│   └── _background_task.py
├── services/
│   ├── __init__.py
│   └── _background_task.py
├── schemas/
│   ├── __init__.py
│   └── _background_task.py
├── deps.py
├── guards.py
├── listeners.py
└── jobs.py                              # SAQ helper utilities (provide_task_context, etc.)
```

### Schemas

```python
# schemas/_background_task.py

class BackgroundTaskList(CamelizedBaseStruct):
    """Summary representation for list views."""
    id: UUID
    task_type: str
    status: str
    progress: int
    entity_type: str | None
    entity_id: UUID | None
    initiated_by_id: UUID | None
    initiated_by_name: str | None           # Denormalized from User relationship
    saq_job_key: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime

class BackgroundTaskDetail(CamelizedBaseStruct):
    """Full representation including payload/result."""
    id: UUID
    task_type: str
    status: str
    progress: int
    entity_type: str | None
    entity_id: UUID | None
    team_id: UUID
    initiated_by_id: UUID | None
    initiated_by_name: str | None
    payload: dict | None
    result: dict | None
    error_message: str | None
    saq_job_key: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime

class BackgroundTaskCreate(CamelizedBaseStruct):
    """Internal-only schema for creating task records."""
    task_type: str
    team_id: UUID
    initiated_by_id: UUID | None = None
    entity_type: str | None = None
    entity_id: UUID | None = None
    payload: dict | None = None

class BackgroundTaskUpdate(CamelizedBaseStruct, omit_defaults=True):
    """Internal-only schema for updating task records."""
    status: str | UnsetType = UNSET
    progress: int | UnsetType = UNSET
    result: dict | UnsetType | None = UNSET
    error_message: str | UnsetType | None = UNSET
    saq_job_key: str | UnsetType | None = UNSET
    started_at: datetime | UnsetType | None = UNSET
    completed_at: datetime | UnsetType | None = UNSET
```

Note: `BackgroundTaskCreate` and `BackgroundTaskUpdate` are **not** exposed to the REST API. Task records are created by other domain services when they enqueue SAQ jobs, and updated by SAQ job functions as they execute. The API only exposes read and cancel operations.

### API Endpoints

| Method | Path | Operation | Description |
|---|---|---|---|
| `GET` | `/api/tasks` | `ListTasks` | List tasks for the current user's team (paginated, filterable by type, status, entity) |
| `GET` | `/api/tasks/active` | `ListActiveTasks` | List pending/running tasks for the current user (lightweight, no pagination) |
| `GET` | `/api/tasks/{task_id}` | `GetTask` | Get full task detail including payload and result |
| `POST` | `/api/tasks/{task_id}/cancel` | `CancelTask` | Cancel a pending or running task |

#### Filter Parameters for `GET /api/tasks`

| Parameter | Type | Description |
|---|---|---|
| `status` | `string` | Filter by status (e.g., `pending`, `failed`) |
| `task_type` | `string` | Filter by task type prefix (e.g., `device`, `device.reboot`) |
| `entity_type` | `string` | Filter by related entity type |
| `entity_id` | `UUID` | Filter by related entity ID |
| `initiated_by_id` | `UUID` | Filter by initiating user |
| `created_before` | `datetime` | Tasks created before this timestamp |
| `created_after` | `datetime` | Tasks created after this timestamp |

#### `POST /api/tasks/{task_id}/cancel` Response

Returns the updated `BackgroundTaskDetail` with `status=cancelled`. If the task has already completed or failed, returns `409 Conflict`. If the task is `running`, the endpoint sets `status=cancelled` and attempts to abort the SAQ job (best-effort; the SAQ worker checks for cancellation cooperatively).

### Guards

- `requires_task_access` -- User belongs to the same team as the task, or is superuser.
- `requires_active_team_member` -- Standard check that the user is an active member of a team (reuse from existing guard patterns).

### Service Logic

#### `BackgroundTaskService`

Extends `SQLAlchemyAsyncRepositoryService[BackgroundTask]`.

Core methods:

```python
async def create_task(
    self,
    task_type: str,
    team_id: UUID,
    initiated_by_id: UUID | None = None,
    entity_type: str | None = None,
    entity_id: UUID | None = None,
    payload: dict | None = None,
) -> BackgroundTask:
    """Create a new pending task record."""

async def start_task(self, task: BackgroundTask) -> BackgroundTask:
    """Mark task as running and set started_at."""

async def update_progress(self, task: BackgroundTask, progress: int) -> BackgroundTask:
    """Update percentage progress (0-100)."""

async def complete_task(
    self, task: BackgroundTask, result: dict | None = None
) -> BackgroundTask:
    """Mark task as completed, set completed_at and optional result."""

async def fail_task(
    self, task: BackgroundTask, error_message: str
) -> BackgroundTask:
    """Mark task as failed, set completed_at and error_message."""

async def cancel_task(self, task: BackgroundTask) -> BackgroundTask:
    """Mark task as cancelled, set completed_at. Attempt SAQ job abort."""

async def list_active_for_user(self, user_id: UUID) -> list[BackgroundTask]:
    """Return all pending/running tasks initiated by the given user."""

async def cleanup_stale_tasks(self, older_than_days: int = 30) -> int:
    """Delete completed/failed/cancelled tasks older than the threshold."""
```

#### `BackgroundTaskService` Integration: `enqueue_tracked_task`

A high-level convenience method that creates the DB record and enqueues the SAQ job in one call. This is the primary entry point for other domain services.

```python
async def enqueue_tracked_task(
    self,
    task_type: str,
    job_function: str,                     # Dotted path to SAQ job function
    team_id: UUID,
    initiated_by_id: UUID | None = None,
    entity_type: str | None = None,
    entity_id: UUID | None = None,
    payload: dict | None = None,
    timeout: int = 300,
) -> BackgroundTask:
    """Create a tracked task record and enqueue the corresponding SAQ job.

    The SAQ job receives `task_id=str(task.id)` as a keyword argument.
    """
    task = await self.create_task(
        task_type=task_type,
        team_id=team_id,
        initiated_by_id=initiated_by_id,
        entity_type=entity_type,
        entity_id=entity_id,
        payload=payload,
    )
    queue = await get_task_queue()
    job = await queue.enqueue(
        job_function,
        task_id=str(task.id),
        **(payload or {}),
        timeout=timeout,
    )
    task = await self.update(
        item_id=task.id,
        data={"saq_job_key": job.key},
        auto_commit=True,
    )
    return task
```

### SAQ Integration Pattern

#### Context Manager for Job Functions

`src/py/app/domain/tasks/jobs.py` provides a context manager that SAQ job functions use to interact with the tracking layer.

```python
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from app.domain.tasks import deps as task_deps
from app.lib.deps import provide_services


@asynccontextmanager
async def provide_task_context(
    ctx: Context,
    task_id: str,
) -> AsyncIterator[tuple[BackgroundTaskService, BackgroundTask]]:
    """Context manager for SAQ jobs that need task tracking.

    Usage in a SAQ job function:

        async def device_reboot_job(ctx: dict, *, task_id: str) -> dict:
            async with provide_task_context(ctx, task_id) as (task_service, task):
                await task_service.start_task(task)
                # ... do work ...
                await task_service.update_progress(task, 50)
                # ... more work ...
                await task_service.complete_task(task, result={"rebooted": True})
            return {"status": "completed"}

    On unhandled exception, automatically marks the task as failed.
    """
    async with provide_services(task_deps.provide_background_task_service) as (task_service,):
        task = await task_service.get(task_id)
        try:
            yield task_service, task
        except Exception as exc:
            await task_service.fail_task(task, error_message=str(exc))
            raise
```

#### Example: Device Reboot Job

```python
# src/py/app/domain/devices/jobs.py

async def device_reboot_job(ctx: dict, *, task_id: str, device_id: str) -> dict:
    """SAQ job for rebooting a device."""
    from app.domain.tasks.jobs import provide_task_context

    async with provide_task_context(ctx, task_id) as (task_service, task):
        await task_service.start_task(task)

        # Phase 1: Send reboot command to device
        await task_service.update_progress(task, 25)
        # ... send SIP NOTIFY or provisioning API call ...

        # Phase 2: Wait for device to go offline
        await task_service.update_progress(task, 50)
        # ... poll device status ...

        # Phase 3: Wait for device to come back online
        await task_service.update_progress(task, 75)
        # ... poll device status ...

        await task_service.complete_task(task, result={"device_id": device_id, "rebooted": True})

    return {"status": "completed"}
```

#### Example: Controller Enqueuing a Tracked Task

```python
# In a device controller endpoint:

@post("/{device_id:uuid}/reboot")
async def reboot_device(
    self,
    device_id: UUID,
    task_service: BackgroundTaskService,
    request: Request,
) -> BackgroundTaskDetail:
    device = await self.service.get(device_id)
    task = await task_service.enqueue_tracked_task(
        task_type="device.reboot",
        job_function="app.domain.devices.jobs.device_reboot_job",
        team_id=device.team_id,
        initiated_by_id=request.user.id,
        entity_type="device",
        entity_id=device.id,
        payload={"device_id": str(device.id)},
        timeout=120,
    )
    return BackgroundTaskDetail.from_orm(task)
```

### SAQ Queue Registration

New job functions must be registered in the SAQ queue config at `src/py/app/lib/settings.py`. The `tasks` list in `QueueConfig` needs each job function that may be enqueued.

```python
# In SaqSettings.get_config():
tasks=[
    system_jobs.cleanup_auth_tokens,
    account_jobs.refresh_oauth_tokens,
    device_jobs.device_reboot_job,         # Phase 2
    device_jobs.device_provision_job,       # Phase 2
    device_jobs.device_reprovision_job,     # Phase 2
    extension_jobs.extension_create_job,    # Phase 3
    extension_jobs.extension_update_job,    # Phase 3
    extension_jobs.extension_delete_job,    # Phase 3
    fax_jobs.fax_send_job,                  # Phase 4
    fax_jobs.fax_receive_process_job,       # Phase 4
    task_jobs.cleanup_stale_tasks,          # Phase 1
],
```

### Cron Job: Stale Task Cleanup

A scheduled task that runs daily to remove completed/failed/cancelled tasks older than a configurable threshold (default 30 days).

```python
# src/py/app/domain/tasks/jobs.py

async def cleanup_stale_tasks(ctx: Context) -> dict[str, int]:
    """Remove completed/failed/cancelled tasks older than 30 days."""
    async with provide_services(task_deps.provide_background_task_service) as (task_service,):
        count = await task_service.cleanup_stale_tasks(older_than_days=30)
    return {"deleted": count}
```

Registered as a `CronJob` in the queue config:

```python
CronJob(
    function=task_jobs.cleanup_stale_tasks,
    cron="0 3 * * *",       # Daily at 3:00 AM
    timeout=300,
    ttl=1800,
),
```

### Event Listeners

- `background_task_completed` -- Emit a `Notification` record so the user sees a toast.
- `background_task_failed` -- Emit a `Notification` record with error details and action URL to the task detail page.

```python
# listeners.py

@listener("background_task_completed")
async def on_task_completed(task: BackgroundTask) -> None:
    """Create an in-app notification when a task completes."""
    # Create Notification with category="task", action_url=f"/tasks/{task.id}"

@listener("background_task_failed")
async def on_task_failed(task: BackgroundTask) -> None:
    """Create an in-app notification when a task fails."""
    # Create Notification with category="task", action_url=f"/tasks/{task.id}"
```

---

## Task Type Registry

A canonical list of task types used across domains. Enforced by convention, not a database constraint, to allow easy extension.

| Task Type | Domain | Description |
|---|---|---|
| `device.reboot` | devices | Reboot a device via SIP NOTIFY or provisioning API |
| `device.provision` | devices | Initial provisioning of a new device |
| `device.reprovision` | devices | Re-provision an existing device |
| `extension.create` | voice | Create an extension on the external PBX |
| `extension.update` | voice | Update extension settings on the PBX |
| `extension.delete` | voice | Delete an extension from the PBX |
| `fax.send` | fax | Transmit an outbound fax via Telnyx |
| `fax.receive_process` | fax | Process a received fax (convert, store, email) |
| `voicemail.transcribe` | voicemail | Transcribe a voicemail message to text (future) |
| `data.sync` | system | Sync data from external provider (future) |
| `report.generate` | analytics | Generate a report export (future) |

---

## Frontend Structure

```
src/js/web/src/
├── routes/_app/tasks/
│   ├── index.tsx                          # Task list page
│   └── $taskId/
│       └── index.tsx                      # Task detail page
├── components/tasks/
│   ├── task-list.tsx                      # Filterable task table
│   ├── task-row.tsx                       # Individual task row
│   ├── task-status-badge.tsx              # Color-coded status indicator
│   ├── task-progress-bar.tsx              # Progress percentage bar
│   ├── task-detail-card.tsx               # Full detail view
│   ├── task-payload-viewer.tsx            # JSON viewer for payload/result
│   ├── task-cancel-button.tsx             # Cancel with confirmation dialog
│   └── active-task-indicator.tsx          # Header indicator for running tasks
└── lib/api/hooks/tasks.ts
```

### Pages

#### Task List (`/tasks`)
- Table of tasks with columns: type, status, progress, initiated by, entity, started, completed.
- Status badge with color coding: pending (yellow), running (blue), completed (green), failed (red), cancelled (gray).
- Progress bar for running tasks.
- Filter controls: status dropdown, task type dropdown, date range picker.
- Search by entity type or task type.
- Click row to navigate to detail view.
- Cancel button for pending/running tasks.
- Paginated with default sort by `created_at` descending.

#### Task Detail (`/tasks/:taskId`)
- **Header**: Task type, status badge, progress bar (if running).
- **Metadata section**: Initiated by, team, entity link (navigates to entity page if applicable), created/started/completed timestamps.
- **Payload section**: Collapsible JSON viewer showing input parameters.
- **Result section** (if completed): Collapsible JSON viewer showing output data.
- **Error section** (if failed): Error message displayed in an alert/callout component.
- **Actions**: Cancel button (if pending/running).
- Auto-refresh every 3 seconds while task is pending or running.

#### Active Task Indicator (Header Component)
- Small badge or icon in the app header/nav showing count of active (pending + running) tasks for the current user.
- Clicking opens a dropdown/popover listing active tasks with status and progress.
- Each item links to the task detail page.
- Polls `GET /api/tasks/active` every 10 seconds.
- Hidden when there are no active tasks.

#### Toast Notifications
- When `GET /api/tasks/active` detects a task has transitioned from `running` to `completed` or `failed`, display a toast notification.
- Completed: success toast with task type label and "View" link.
- Failed: error toast with task type label and error preview.
- Toasts auto-dismiss after 8 seconds but can be closed manually.

### React Query Hooks

```typescript
// lib/api/hooks/tasks.ts
useTasks(filters)                        // GET /api/tasks (paginated)
useTask(taskId)                          // GET /api/tasks/:id
useActiveTasks()                         // GET /api/tasks/active (polls every 10s)
useCancelTask(taskId)                    // POST /api/tasks/:id/cancel
```

#### Polling Configuration

```typescript
// useActiveTasks uses refetchInterval: 10_000 (10 seconds)
// useTask uses refetchInterval: 3_000 when status is "pending" or "running", disabled otherwise
```

---

## Cross-Domain Integration

### How Other Domains Use the Task Queue

Other domain services create tracked tasks by depending on `BackgroundTaskService`. The pattern is:

1. **Controller** receives user request (e.g., `POST /api/devices/{id}/reboot`).
2. **Controller** calls `task_service.enqueue_tracked_task(...)` with the appropriate task type and payload.
3. **Controller** returns `BackgroundTaskDetail` as the HTTP response (status 202 Accepted).
4. **SAQ job** uses `provide_task_context()` to pick up the task record and update progress/status.
5. **Frontend** uses the returned task ID to poll for updates or navigates to the task detail page.

### Integration Points

| Domain | Integration | Notes |
|---|---|---|
| **devices** | `device.reboot`, `device.provision`, `device.reprovision` | Device controller returns task detail; device detail page shows related tasks |
| **voice** | `extension.create`, `extension.update`, `extension.delete` | Extension CRUD endpoints may return tasks when PBX sync is needed |
| **fax** | `fax.send`, `fax.receive_process` | Send fax returns task; fax message detail links to processing task |
| **notifications** | Task completion/failure events | `background_task_completed` and `background_task_failed` listeners create `Notification` records |
| **admin** | Admin task overview | Admin users can see all tasks across all teams |

### Entity Linking

When `entity_type` and `entity_id` are set on a task, the frontend can render a link to the related entity's detail page. The mapping is:

| `entity_type` | Route |
|---|---|
| `device` | `/devices/:entityId` |
| `extension` | `/voice/extensions/:entityId` |
| `fax_message` | `/fax/messages/:entityId` |
| `fax_number` | `/fax/numbers/:entityId` |

---

## Sub-Features & Tasks

### Phase 1: Core Infrastructure
- [x] Create `BackgroundTaskStatus` enum model in `src/py/app/db/models/_background_task_status.py`
- [x] Create `BackgroundTask` database model in `src/py/app/db/models/_background_task.py`
- [x] Export both from `src/py/app/db/models/__init__.py`
- [x] Create Alembic migration
- [x] Create `BackgroundTaskService` with core methods (`create_task`, `start_task`, `update_progress`, `complete_task`, `fail_task`, `cancel_task`)
- [x] Implement `enqueue_tracked_task` convenience method
- [x] Create `provide_task_context` context manager in `jobs.py`
- [x] Create schemas (`BackgroundTaskList`, `BackgroundTaskDetail`, `BackgroundTaskCreate`, `BackgroundTaskUpdate`)
- [x] Create `BackgroundTaskController` with REST endpoints
- [x] Add dependency providers in `deps.py`
- [x] Add `requires_task_access` guard
- [x] Add `cleanup_stale_tasks` cron job and register in SAQ config
- [x] Regenerate TypeScript types (`make types`)

### Phase 2: Device Task Jobs
- [x] Create `src/py/app/domain/devices/jobs.py` with `device_reboot_job`
- [x] Create `device_provision_job` and `device_reprovision_job`
- [x] Update device controller reboot/reprovision endpoints to use `enqueue_tracked_task`
- [x] Register device job functions in SAQ queue config `tasks` list
- [x] Update device controller responses to return `BackgroundTaskDetail` (HTTP 202)

### Phase 3: Extension Task Jobs
- [x] Create `src/py/app/domain/voice/jobs.py` with `extension_create_job`
- [x] Create `extension_update_job` and `extension_delete_job`
- [x] Update extension controller to use tracked tasks for PBX-sync operations
- [x] Register extension job functions in SAQ queue config `tasks` list

### Phase 4: Fax Task Jobs
- [x] Create `src/py/app/domain/fax/jobs.py` with `fax_send_job`
- [x] Create `fax_receive_process_job`
- [x] Update fax send endpoint to use `enqueue_tracked_task`
- [x] Register fax job functions in SAQ queue config `tasks` list

### Phase 5: Frontend -- Task List & Detail
- [x] Create `useTasks`, `useTask`, `useActiveTasks`, `useCancelTask` React Query hooks
- [x] Build `TaskStatusBadge` component (color-coded by status)
- [x] Build `TaskProgressBar` component
- [x] Build `TaskPayloadViewer` component (collapsible JSON viewer)
- [x] Build task list page at `/tasks` with filtering, sorting, pagination
- [x] Build task detail page at `/tasks/:taskId` with auto-refresh
- [x] Add cancel button with confirmation dialog

### Phase 6: Frontend -- Active Indicator & Notifications
- [x] Build `ActiveTaskIndicator` header component with polling
- [x] Implement toast notifications on task completion/failure transitions — already implemented in events.ts SSE hook
- [x] Add `background_task_completed` event listener to create `Notification` records
- [x] Add `background_task_failed` event listener to create `Notification` records
- [x] Add entity-type link rendering in task detail and task list
- [x] Add task count to relevant entity detail pages (e.g., device detail shows recent tasks) — done in v0.160.0, device detail has Recent Tasks card

### Phase 7: Admin Views & Monitoring
- [x] Add `/admin/tasks` management page (all tasks across all teams) — done in v0.161.0 at /admin/tasks
- [x] Add admin filters: team, user, date range, status — done in v0.161.0, has status/taskType/entityType filters
- [x] Add bulk actions: retry failed tasks, cancel pending tasks, purge old tasks — done in v0.161.0, cancel/delete/export bulk actions
- [ ] Add task statistics dashboard (counts by status, average duration by type)
- [ ] Add audit log entries for task cancellations
