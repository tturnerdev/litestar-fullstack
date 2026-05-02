# Feature: Real-Time Updates (Server-Sent Events)

## Summary

The Real-Time Updates feature replaces frontend polling with a push-based architecture using Server-Sent Events (SSE). An authenticated SSE endpoint streams events to the browser as they happen, driven by Redis Pub/Sub as the event bus. When backend services update task status, device state, or create notifications, they publish an event to Redis. The SSE endpoint picks it up and pushes it to connected clients, enabling instant UI feedback without page refreshes.

This feature does **not** replace React Query caching or REST endpoints. SSE acts as a signal layer: when an event arrives, the frontend invalidates the appropriate React Query cache key so the next render fetches fresh data via the existing REST API.

---

## Domain Module

**Backend**: `src/py/app/domain/events/`
**Frontend**: `src/js/web/src/lib/api/hooks/events.ts` + `src/js/web/src/components/events/`

---

## Event Types

| Event Name | Source | Description |
|---|---|---|
| `task.updated` | SAQ job (via `BackgroundTaskService`) | Task status or progress changed (pending->running, progress %, etc.) |
| `task.completed` | SAQ job (via `BackgroundTaskService`) | Task finished successfully |
| `task.failed` | SAQ job (via `BackgroundTaskService`) | Task raised an error |
| `device.status_changed` | Device status sync / provisioning jobs | Device went online, offline, rebooting, error, etc. |
| `notification.created` | Any domain listener that creates a `Notification` | New in-app notification for the user |
| `entity.updated` | Any service after a write operation | Generic cache invalidation signal for a specific entity type |

---

## Event Format (SSE Wire Protocol)

Events follow the standard SSE format with `event:` and `data:` fields. The `data:` payload is a JSON object.

### `task.updated`

```
event: task.updated
data: {"taskId": "01961234-...", "taskType": "device.reboot", "status": "running", "progress": 50, "entityType": "device", "entityId": "01961234-..."}
```

### `task.completed`

```
event: task.completed
data: {"taskId": "01961234-...", "taskType": "device.reboot", "status": "completed", "entityType": "device", "entityId": "01961234-...", "result": {"rebooted": true}}
```

### `task.failed`

```
event: task.failed
data: {"taskId": "01961234-...", "taskType": "device.reboot", "status": "failed", "entityType": "device", "entityId": "01961234-...", "errorMessage": "Connection refused"}
```

### `device.status_changed`

```
event: device.status_changed
data: {"deviceId": "01961234-...", "status": "online", "previousStatus": "offline", "deviceName": "Desk Phone - Office"}
```

### `notification.created`

```
event: notification.created
data: {"notificationId": "01961234-...", "title": "Device reboot completed", "category": "device", "actionUrl": "/devices/01961234-..."}
```

### `entity.updated`

```
event: entity.updated
data: {"entityType": "device", "entityId": "01961234-...", "action": "updated"}
```

All payloads use camelCase field names to match the frontend schema convention.

---

## Backend Architecture

### Redis Pub/Sub Channel Design

Events are published to team-scoped Redis channels. Each team has its own channel so the SSE endpoint only subscribes to channels for teams the authenticated user belongs to.

| Channel Pattern | Example | Subscribers |
|---|---|---|
| `events:team:{team_id}` | `events:team:01961234-abcd-...` | All members of that team |
| `events:user:{user_id}` | `events:user:01961234-abcd-...` | Only the specific user (for user-targeted notifications) |

Task, device, and entity events publish to the team channel. Notification events publish to the user channel since notifications are per-user.

### Backend Structure

```
src/py/app/domain/events/
├── __init__.py
├── controllers/
│   ├── __init__.py
│   └── _stream.py                     # SSE endpoint controller
├── services/
│   ├── __init__.py
│   ├── _broadcaster.py                # EventBroadcaster: publishes events to Redis
│   └── _subscriber.py                 # EventSubscriber: subscribes to Redis channels for SSE
├── schemas/
│   ├── __init__.py
│   └── _event.py                      # Event payload schemas
├── deps.py
└── guards.py
```

### `EventBroadcaster` Service

A lightweight utility (not a repository service since it has no database model) that any domain service can call to publish events to Redis Pub/Sub.

```python
# services/_broadcaster.py

class EventBroadcaster:
    """Publishes real-time events to Redis Pub/Sub channels."""

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def publish_to_team(
        self,
        team_id: UUID,
        event_type: str,
        data: dict,
    ) -> None:
        """Publish an event to all members of a team."""
        channel = f"events:team:{team_id}"
        payload = {"event": event_type, "data": data}
        await self.redis.publish(channel, msgspec.json.encode(payload))

    async def publish_to_user(
        self,
        user_id: UUID,
        event_type: str,
        data: dict,
    ) -> None:
        """Publish an event to a specific user."""
        channel = f"events:user:{user_id}"
        payload = {"event": event_type, "data": data}
        await self.redis.publish(channel, msgspec.json.encode(payload))

    async def publish_task_update(
        self,
        team_id: UUID,
        task_id: UUID,
        task_type: str,
        status: str,
        progress: int = 0,
        entity_type: str | None = None,
        entity_id: UUID | None = None,
        result: dict | None = None,
        error_message: str | None = None,
    ) -> None:
        """Convenience method for task lifecycle events.

        Chooses the event type (task.updated / task.completed / task.failed)
        based on the status value.
        """
        event_type = {
            "completed": "task.completed",
            "failed": "task.failed",
        }.get(status, "task.updated")
        data = {
            "taskId": str(task_id),
            "taskType": task_type,
            "status": status,
            "progress": progress,
        }
        if entity_type:
            data["entityType"] = entity_type
        if entity_id:
            data["entityId"] = str(entity_id)
        if result:
            data["result"] = result
        if error_message:
            data["errorMessage"] = error_message
        await self.publish_to_team(team_id, event_type, data)

    async def publish_device_status_changed(
        self,
        team_id: UUID,
        device_id: UUID,
        device_name: str,
        status: str,
        previous_status: str,
    ) -> None:
        """Publish a device status change event."""
        await self.publish_to_team(team_id, "device.status_changed", {
            "deviceId": str(device_id),
            "status": status,
            "previousStatus": previous_status,
            "deviceName": device_name,
        })

    async def publish_entity_updated(
        self,
        team_id: UUID,
        entity_type: str,
        entity_id: UUID,
        action: str = "updated",
    ) -> None:
        """Publish a generic entity update event for cache invalidation."""
        await self.publish_to_team(team_id, "entity.updated", {
            "entityType": entity_type,
            "entityId": str(entity_id),
            "action": action,
        })

    async def publish_notification_created(
        self,
        user_id: UUID,
        notification_id: UUID,
        title: str,
        category: str,
        action_url: str | None = None,
    ) -> None:
        """Publish a notification creation event to a specific user."""
        await self.publish_to_user(user_id, "notification.created", {
            "notificationId": str(notification_id),
            "title": title,
            "category": category,
            "actionUrl": action_url,
        })
```

### `EventSubscriber` Service

Manages the Redis Pub/Sub subscription for a single SSE connection. One instance per connected client.

```python
# services/_subscriber.py

class EventSubscriber:
    """Subscribes to Redis Pub/Sub channels and yields events for SSE streaming."""

    def __init__(self, redis: Redis) -> None:
        self.redis = redis
        self.pubsub: PubSub | None = None

    async def subscribe(
        self,
        team_ids: list[UUID],
        user_id: UUID,
    ) -> None:
        """Subscribe to all relevant channels for the authenticated user."""
        self.pubsub = self.redis.pubsub()
        channels = [f"events:team:{tid}" for tid in team_ids]
        channels.append(f"events:user:{user_id}")
        await self.pubsub.subscribe(*channels)

    async def listen(self) -> AsyncIterator[tuple[str, dict]]:
        """Yield (event_type, data) tuples as they arrive from Redis."""
        if not self.pubsub:
            raise RuntimeError("Must call subscribe() before listen()")
        async for message in self.pubsub.listen():
            if message["type"] != "message":
                continue
            payload = msgspec.json.decode(message["data"])
            yield payload["event"], payload["data"]

    async def unsubscribe(self) -> None:
        """Clean up the subscription."""
        if self.pubsub:
            await self.pubsub.unsubscribe()
            await self.pubsub.close()
```

### SSE Endpoint Controller

```python
# controllers/_stream.py

class EventStreamController(Controller):
    """SSE endpoint for real-time event streaming."""

    path = "/api/events"
    tags = ["Events"]

    @get(
        "/stream",
        operation_id="StreamEvents",
        summary="Stream real-time events via SSE",
        media_type="text/event-stream",
        guards=[requires_active_session],
    )
    async def stream_events(self, request: Request) -> Stream:
        """Open an SSE connection for the authenticated user.

        The stream delivers events scoped to the user's team(s) and
        user-specific notifications. The connection stays open
        indefinitely; the client should reconnect on disconnect.
        """
        user = request.user
        team_ids = await self._get_user_team_ids(user.id)
        redis = request.app.stores.get("redis").redis  # Access Redis from app stores
        subscriber = EventSubscriber(redis)
        await subscriber.subscribe(team_ids=team_ids, user_id=user.id)

        async def event_generator() -> AsyncIterator[bytes]:
            try:
                async for event_type, data in subscriber.listen():
                    yield f"event: {event_type}\ndata: {msgspec.json.encode(data).decode()}\n\n".encode()
            finally:
                await subscriber.unsubscribe()

        return Stream(iterator=event_generator(), media_type="text/event-stream")
```

### Event Payload Schemas

```python
# schemas/_event.py

class TaskEvent(CamelizedBaseStruct):
    """Payload for task.updated / task.completed / task.failed events."""
    task_id: UUID
    task_type: str
    status: str
    progress: int = 0
    entity_type: str | None = None
    entity_id: UUID | None = None
    result: dict | None = None
    error_message: str | None = None

class DeviceStatusEvent(CamelizedBaseStruct):
    """Payload for device.status_changed events."""
    device_id: UUID
    status: str
    previous_status: str
    device_name: str

class NotificationEvent(CamelizedBaseStruct):
    """Payload for notification.created events."""
    notification_id: UUID
    title: str
    category: str
    action_url: str | None = None

class EntityUpdatedEvent(CamelizedBaseStruct):
    """Payload for entity.updated events."""
    entity_type: str
    entity_id: UUID
    action: str = "updated"
```

### Dependency Provider

```python
# deps.py

async def provide_event_broadcaster(state: State) -> EventBroadcaster:
    """Provide an EventBroadcaster instance using the app's Redis connection."""
    redis = state.stores.get("redis").redis
    return EventBroadcaster(redis)
```

The `EventBroadcaster` is injected as a dependency into any controller or service that needs to publish events. It is not a repository service so it does not use `create_service_dependencies()`.

### Guards

```python
# guards.py

def requires_active_session(connection: ASGIConnection, handler: BaseRouteHandler) -> None:
    """Guard that ensures the request has an active authenticated session.

    The SSE endpoint must be protected the same way as other API endpoints.
    Raises PermissionDeniedException if not authenticated.
    """
    if not connection.user:
        raise PermissionDeniedException(detail="Authentication required for event streaming.")
```

### Heartbeat / Keep-Alive

The SSE endpoint sends a comment-only keep-alive every 30 seconds to prevent proxy/load-balancer timeouts:

```
: heartbeat

```

This is a standard SSE comment (lines starting with `:`) that the browser's `EventSource` API ignores.

---

## Integration Points

### Task Queue Integration

The `BackgroundTaskService` methods (`start_task`, `update_progress`, `complete_task`, `fail_task`) are the natural integration point. After updating the database record, each method also calls `EventBroadcaster.publish_task_update()`.

```python
# In BackgroundTaskService (updated methods):

async def start_task(self, task: BackgroundTask) -> BackgroundTask:
    """Mark task as running, publish event."""
    task = await self._start_task_db(task)
    await self.broadcaster.publish_task_update(
        team_id=task.team_id, task_id=task.id,
        task_type=task.task_type, status="running",
        entity_type=task.entity_type, entity_id=task.entity_id,
    )
    return task

async def update_progress(self, task: BackgroundTask, progress: int) -> BackgroundTask:
    """Update progress, publish event."""
    task = await self._update_progress_db(task, progress)
    await self.broadcaster.publish_task_update(
        team_id=task.team_id, task_id=task.id,
        task_type=task.task_type, status=task.status,
        progress=progress,
        entity_type=task.entity_type, entity_id=task.entity_id,
    )
    return task

async def complete_task(self, task: BackgroundTask, result: dict | None = None) -> BackgroundTask:
    """Mark completed, publish event."""
    task = await self._complete_task_db(task, result)
    await self.broadcaster.publish_task_update(
        team_id=task.team_id, task_id=task.id,
        task_type=task.task_type, status="completed",
        progress=100,
        entity_type=task.entity_type, entity_id=task.entity_id,
        result=result,
    )
    return task

async def fail_task(self, task: BackgroundTask, error_message: str) -> BackgroundTask:
    """Mark failed, publish event."""
    task = await self._fail_task_db(task, error_message)
    await self.broadcaster.publish_task_update(
        team_id=task.team_id, task_id=task.id,
        task_type=task.task_type, status="failed",
        entity_type=task.entity_type, entity_id=task.entity_id,
        error_message=error_message,
    )
    return task
```

### Device Domain Integration

When the device status sync background task detects a status change, it calls `EventBroadcaster.publish_device_status_changed()`. This replaces the need for the frontend to poll device status.

### Notification Domain Integration

When any domain listener creates a `Notification` record (e.g., `background_task_completed`, `voicemail_received`), it also calls `EventBroadcaster.publish_notification_created()` to push the notification to the user in real time.

### Cross-Domain Summary

| Domain | Publishes | Channel |
|---|---|---|
| **tasks** | `task.updated`, `task.completed`, `task.failed` | `events:team:{team_id}` |
| **devices** | `device.status_changed`, `entity.updated` | `events:team:{team_id}` |
| **notifications** | `notification.created` | `events:user:{user_id}` |
| **voice** | `entity.updated` (extension settings changed) | `events:team:{team_id}` |
| **fax** | `entity.updated` (fax message received/sent) | `events:team:{team_id}` |
| **support** | `entity.updated` (ticket status changed) | `events:team:{team_id}` |

---

## Frontend Architecture

### `useEventStream()` Hook

The primary hook that manages the SSE connection lifecycle, auto-reconnect, and event dispatching.

```typescript
// lib/api/hooks/events.ts

function useEventStream(): void
```

**Behavior:**

1. Opens an `EventSource` connection to `GET /api/events/stream` on mount.
2. Registers handlers for each event type.
3. On connection error, implements exponential backoff reconnect (1s, 2s, 4s, 8s, max 30s).
4. On successful reconnect, resets backoff timer.
5. Cleans up the `EventSource` on unmount.
6. Only connects when the user is authenticated (check auth state from Zustand store).

### Event Handlers (React Query Cache Invalidation)

Each event type maps to a specific cache invalidation and/or UI action:

| Event | React Query Invalidation | UI Action |
|---|---|---|
| `task.updated` | `["tasks"]`, `["tasks", taskId]`, `["tasks", "active"]` | Update active task indicator |
| `task.completed` | `["tasks"]`, `["tasks", taskId]`, `["tasks", "active"]` | Success toast with task type and "View" link |
| `task.failed` | `["tasks"]`, `["tasks", taskId]`, `["tasks", "active"]` | Error toast with task type and error preview |
| `device.status_changed` | `["devices"]`, `["devices", deviceId]` | Update device status badge in real time |
| `notification.created` | `["notifications"]`, `["notifications", "unread-count"]` | Increment notification badge, show toast |
| `entity.updated` | `[entityType + "s"]`, `[entityType + "s", entityId]` | None (silent cache invalidation) |

### Frontend Structure

```
src/js/web/src/
├── lib/api/hooks/
│   └── events.ts                          # useEventStream() hook
├── components/events/
│   └── event-stream-provider.tsx          # Provider component mounted in app layout
└── lib/
    └── event-handlers.ts                  # Event type -> handler mapping
```

### `EventStreamProvider` Component

A provider component mounted once in the app layout (`_app.tsx`) that activates the SSE connection for the authenticated session.

```typescript
// components/events/event-stream-provider.tsx

function EventStreamProvider({ children }: { children: React.ReactNode }): JSX.Element {
    useEventStream()
    return <>{children}</>
}
```

Mounted in the app layout:

```tsx
// routes/_app.tsx (inside the authenticated layout)
<EventStreamProvider>
    <Outlet />
</EventStreamProvider>
```

### Toast Notification Integration

Task completion and failure events trigger toast notifications using the existing shadcn/ui toast system.

```typescript
// In event-handlers.ts

function handleTaskCompleted(data: TaskEvent): void {
    const label = formatTaskType(data.taskType)  // "device.reboot" -> "Device Reboot"
    toast.success(`${label} completed`, {
        description: `Task finished successfully.`,
        action: { label: "View", onClick: () => navigate(`/tasks/${data.taskId}`) },
        duration: 8000,
    })
    queryClient.invalidateQueries({ queryKey: ["tasks"] })
    queryClient.invalidateQueries({ queryKey: ["tasks", "active"] })
    // Also invalidate the related entity if present
    if (data.entityType) {
        queryClient.invalidateQueries({ queryKey: [data.entityType + "s"] })
    }
}

function handleTaskFailed(data: TaskEvent): void {
    const label = formatTaskType(data.taskType)
    toast.error(`${label} failed`, {
        description: data.errorMessage ?? "An unexpected error occurred.",
        action: { label: "View", onClick: () => navigate(`/tasks/${data.taskId}`) },
        duration: 8000,
    })
    queryClient.invalidateQueries({ queryKey: ["tasks"] })
    queryClient.invalidateQueries({ queryKey: ["tasks", "active"] })
}
```

### Notification Badge Integration

The `notification.created` event increments the unread notification count in real time without waiting for the next poll cycle.

```typescript
function handleNotificationCreated(data: NotificationEvent): void {
    queryClient.invalidateQueries({ queryKey: ["notifications"] })
    queryClient.invalidateQueries({ queryKey: ["notifications", "unread-count"] })
    // Optionally show a subtle toast for high-priority notifications
}
```

### Polling Reduction

With SSE in place, several existing polling intervals can be removed or extended:

| Hook | Current Polling | With SSE |
|---|---|---|
| `useActiveTasks()` | `refetchInterval: 10_000` (10s) | Remove polling; SSE `task.*` events trigger invalidation |
| `useTask(id)` (active) | `refetchInterval: 3_000` (3s) | Remove polling; SSE `task.updated` triggers invalidation |
| `useDevices()` status | Manual refresh | SSE `device.status_changed` triggers invalidation |
| Notification badge | Poll-based | SSE `notification.created` triggers invalidation |

Polling is retained as a fallback: if the SSE connection drops and has not reconnected within 60 seconds, re-enable polling at a reduced interval (30s) until SSE reconnects.

---

## Connection Resilience

### Reconnection Strategy

The `useEventStream()` hook implements reconnect with exponential backoff:

1. On `EventSource.onerror`, close the connection.
2. Wait `delay` seconds (starting at 1s).
3. Attempt reconnect.
4. On success (`EventSource.onopen`), reset delay to 1s.
5. On failure, double the delay (cap at 30s).
6. After 60s of continuous disconnection, re-enable polling as fallback.
7. On reconnect after fallback, disable polling again.

### Server-Side Considerations

- **Heartbeat**: Server sends `:heartbeat\n\n` every 30 seconds to keep the connection alive through proxies.
- **Connection limit**: Track active SSE connections per user. Limit to 3 concurrent connections per user to prevent resource exhaustion (new connections evict the oldest).
- **Graceful shutdown**: On server shutdown, send a final `event: server.shutdown` so clients know to reconnect rather than treating it as an error.

---

## Security Considerations

- The SSE endpoint requires authentication via the same session/token mechanism as all other API endpoints.
- Events are team-scoped: a user only receives events for teams they are a member of. The subscription channels are determined server-side based on the authenticated user's team memberships.
- User-scoped events (notifications) are published to `events:user:{user_id}` which only the owning user subscribes to.
- No sensitive data (credentials, PII beyond names) is included in event payloads. Payloads contain IDs and status values; the client fetches full details via REST.
- Redis Pub/Sub channels are internal to the backend network and not exposed to clients.

---

## Sub-Features & Tasks

### Phase 1: Backend SSE Infrastructure
- [x] Create `src/py/app/domain/events/` domain module structure
- [x] Implement `EventBroadcaster` service with `publish_to_team`, `publish_to_user`, and convenience methods
- [x] Implement `EventSubscriber` service with `subscribe`, `listen`, `unsubscribe`
- [x] Create event payload schemas (`TaskEvent`, `DeviceStatusEvent`, `NotificationEvent`, `EntityUpdatedEvent`)
- [x] Create `EventStreamController` with `GET /api/events/stream` SSE endpoint
- [x] Add `provide_event_broadcaster` dependency provider
- [x] Add `requires_active_session` guard for the SSE endpoint
- [x] Implement 30-second heartbeat keep-alive in the SSE stream
- [x] Implement per-user connection limiting (max 3 concurrent SSE connections)
- [x] Add graceful shutdown event (`server.shutdown`)
- [x] Verify Redis Pub/Sub works with the existing SAQ Redis instance (shared vs. separate connection)

### Phase 2: Wire Task Queue Events
- [x] Inject `EventBroadcaster` into `BackgroundTaskService`
- [x] Publish `task.updated` on `start_task()` and `update_progress()`
- [x] Publish `task.completed` on `complete_task()`
- [x] Publish `task.failed` on `fail_task()`
- [x] Publish `task.updated` with status `cancelled` on `cancel_task()`
- [x] Add integration test: enqueue task, verify SSE receives status transitions

### Phase 3: Frontend SSE Hook + Cache Invalidation
- [x] Implement `useEventStream()` hook with `EventSource` management
- [x] Implement exponential backoff reconnection logic
- [x] Add event handlers for `task.updated`, `task.completed`, `task.failed`
- [x] Add event handler for `device.status_changed`
- [x] Add event handler for `notification.created`
- [x] Add event handler for `entity.updated` (generic cache invalidation)
- [x] Create `EventStreamProvider` component
- [x] Mount `EventStreamProvider` in the authenticated app layout (`_app.tsx`)
- [x] Regenerate TypeScript types (`make types`)

### Phase 4: Toast Notifications for Task Completion/Failure
- [x] Add `handleTaskCompleted` toast with task type label and "View" link
- [x] Add `handleTaskFailed` error toast with error message preview and "View" link
- [x] Add `formatTaskType` utility (`device.reboot` -> `Device Reboot`)
- [x] Verify toasts auto-dismiss after 8 seconds and support manual close
- [x] Test toast behavior when multiple tasks complete in quick succession

### Phase 5: Device Status Events
- [ ] Publish `device.status_changed` from device status sync background task
- [ ] Publish `device.status_changed` from `device_reboot_job` on status transitions
- [ ] Invalidate device list and detail React Query cache on status change events
- [ ] Update `DeviceStatusBadge` component to reflect real-time status without manual refresh

### Phase 6: Notification Badge + Polling Reduction
- [x] Invalidate notification queries on `notification.created` events
- [ ] Publish `notification.created` from notification domain listeners (task completed, voicemail received, etc.)
- [ ] Increment unread notification badge count in real time
- [ ] Remove `refetchInterval` from `useActiveTasks()` (replace with SSE-driven invalidation)
- [ ] Remove `refetchInterval` from `useTask()` for active tasks
- [ ] Implement polling fallback: re-enable 30s polling after 60s of SSE disconnection
- [ ] Disable fallback polling on SSE reconnect
- [ ] End-to-end test: create notification via backend, verify badge updates in browser without refresh
