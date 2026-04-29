# Entity Sync API Reference

## Endpoint

```
GET /api/sync/{domain}/{field}/{value}
```

Looks up and syncs an entity by domain, field name, and value. Requires authentication (any logged-in user).

## Path Parameters

| Parameter | Type   | Description                                      |
|-----------|--------|--------------------------------------------------|
| `domain`  | string | The domain path (may include `/` for sub-domains) |
| `field`   | string | The model field to look up by                    |
| `value`   | string | The value to match (URL-encoded)                 |

## Available Domains

| Domain Path        | Allowed Lookup Fields                   | Status    |
|--------------------|-----------------------------------------|-----------|
| `teams`            | `id`, `name`, `slug`                    | Available |
| `devices`          | `id`, `name`, `mac_address`, `serial_number` | Planned |
| `voice/extensions` | `id`, `extension_number`                | Planned   |
| `voice/numbers`    | `id`, `number`                          | Planned   |
| `fax/numbers`      | `id`, `number`                          | Planned   |
| `support/tickets`  | `id`, `ticket_number`                   | Planned   |
| `locations`        | `id`, `name`                            | Planned   |
| `connections`      | `id`, `name`                            | Planned   |

Domains marked "Planned" are registered in the sync controller but their models and services have not been implemented yet. Requests to these domains will return a `404` until the domain is built.

## Response Format

```json
{
  "synced": true,
  "domain": "teams",
  "field": "id",
  "value": "019c3d26-24d2-71b1-bcdd-351a03522d59",
  "entity": {
    "id": "019c3d26-24d2-71b1-bcdd-351a03522d59",
    "name": "Engineering",
    "slug": "engineering",
    "description": "The engineering team",
    "is_active": true,
    "created_at": "2026-04-20T10:30:00",
    "updated_at": "2026-04-28T17:30:00"
  },
  "syncedAt": "2026-04-28T17:30:00+00:00"
}
```

## Error Responses

### Unknown Domain (404)

```json
{
  "status_code": 404,
  "detail": "Unknown sync domain: invalid-domain"
}
```

### Invalid Field (400)

```json
{
  "status_code": 400,
  "detail": "Field 'invalid_field' is not allowed for domain 'teams'. Allowed fields: id, name, slug"
}
```

### Entity Not Found (404)

```json
{
  "status_code": 404,
  "detail": "Entity not found in 'teams' where name=Nonexistent"
}
```

### Invalid UUID (400)

When looking up by `id`, the value must be a valid UUID:

```json
{
  "status_code": 400,
  "detail": "Invalid UUID: not-a-uuid"
}
```

## URL Encoding

The `value` path parameter is automatically URL-decoded by Litestar. Special characters must be percent-encoded in the request URL:

| Character | Encoded | Example Use Case  |
|-----------|---------|-------------------|
| Space     | `%20`   | Entity names      |
| Colon `:` | `%3A`   | MAC addresses     |
| Plus `+`  | `%2B`   | Phone numbers     |
| Slash `/` | `%2F`   | Composite values  |

### Examples

```
GET /api/sync/teams/name/Engineering%20Team
GET /api/sync/teams/id/019c3d26-24d2-71b1-bcdd-351a03522d59
GET /api/sync/devices/mac_address/AA%3ABB%3ACC%3A11%3A22%3A33
GET /api/sync/voice/extensions/extension_number/1001
GET /api/sync/voice/numbers/number/%2B15551234567
```

## Adding New Domains

To add a new syncable domain, add an entry to the `_DOMAIN_REGISTRY` dictionary in `src/py/app/domain/system/controllers/_sync.py`:

```python
"my-domain": _DomainRegistration(
    model_path="app.db.models.MyModel",
    service_path="app.domain.my_domain.services.MyModelService",
    allowed_fields=frozenset({"id", "name", "other_unique_field"}),
),
```

The model and service are imported lazily, so adding a registry entry for a domain that does not yet exist will not cause import errors. Requests to that domain will return a `404` with a "not available" message until the domain code is implemented.

## Frontend Usage

Use the `useSyncEntity` hook from `src/js/web/src/lib/api/hooks/sync.ts`:

```typescript
import { useSyncEntity } from "@/lib/api/hooks/sync"

function MyComponent({ entityId }: { entityId: string }) {
  const syncEntity = useSyncEntity()

  return (
    <button
      onClick={() => syncEntity.mutate({ domain: "teams", field: "id", value: entityId })}
      disabled={syncEntity.isPending}
    >
      {syncEntity.isPending ? "Syncing..." : "Sync"}
    </button>
  )
}
```
