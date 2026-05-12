# Feature: Object Storage & File Uploads

## Summary

Add first-class file-upload / object-storage support to the application using
[`advanced-alchemy`](https://docs.advanced-alchemy.litestar.dev/)'s `FileObject`
/ `StoredObject` integration backed by [`obstore`](https://developmentseed.org/obstore/).
Files live in an S3-compatible object store; only lightweight metadata
(filename, size, content type, backend key, checksum) is persisted in
PostgreSQL via a `StoredObject` column type.

The production and dev **infrastructure is already in place** — see
`docs/deployment.md` and `tools/deploy/docker/docker-compose.portainer.yml`
(prod, rustfs `storage` service + `storage-init` bucket job) and
`tools/deploy/docker/docker-compose.infra.yml` (dev, rustfs `storage` service).
The standard `AWS_*` / `STORAGE_*` environment variables are already wired into
the `app` and `worker` containers. This feature is the application-side code
that consumes them.

> Status: **planned, not implemented.** This document is the implementation
> plan to be picked up later.

---

## Dependencies

Already present in `pyproject.toml`: `advanced-alchemy[uuid,obstore,pwdlib]`
(the `obstore` extra pulls in `obstore` + advanced-alchemy's `ObstoreBackend`).
No new Python dependencies are expected. If a local-filesystem dev backend that
does not require rustfs is wanted, `advanced-alchemy[fsspec]` could be added,
but the existing dev rustfs container makes that optional.

Frontend: no new deps expected (multipart upload via `fetch`/the existing API
client; progress via `XMLHttpRequest` if a progress bar is desired).

---

## Configuration

### New settings class — `app/lib/settings.py`

Add a `StorageSettings` dataclass (prefix `STORAGE_` / standard `AWS_`), and add
it to the composed `Settings`:

| Env var | Default | Description |
|---|---|---|
| `STORAGE_BACKEND` | `s3` | `s3` (obstore S3 — works against rustfs/MinIO/AWS), `local` (obstore local filesystem, for tests/dev without rustfs), `memory` (tests) |
| `STORAGE_BUCKET` | `uploads` | Bucket / container name |
| `AWS_ENDPOINT_URL` | _(unset)_ | S3 endpoint override; `http://storage:9000` in Docker, unset for real AWS |
| `AWS_ACCESS_KEY_ID` | _(unset)_ | S3 access key |
| `AWS_SECRET_ACCESS_KEY` | _(unset)_ | S3 secret key |
| `AWS_REGION` | `us-east-1` | Region (rustfs ignores it; AWS needs it) |
| `STORAGE_ALLOW_HTTP` | `true` | Allow plain-HTTP endpoint (needed for in-cluster rustfs); set `false` for real AWS |
| `STORAGE_LOCAL_PATH` | `<tmp>/uploads` | Filesystem root when `STORAGE_BACKEND=local` |
| `STORAGE_PRESIGN_EXPIRY` | `3600` | Seconds a presigned download URL is valid |
| `STORAGE_MAX_UPLOAD_BYTES` | `26214400` (25 MiB) | Server-side upload size cap |
| `STORAGE_ALLOWED_CONTENT_TYPES` | `[]` (any) | Optional allow-list of MIME types |

Most of these already exist as env vars on the containers; this just gives the
app a typed view of them.

### Store registry — `app/lib/storage.py` (new)

A small module that builds and registers the backend(s) with advanced-alchemy's
global `storages` registry, exposing a single named backend `"uploads"`:

```python
# app/lib/storage.py  (sketch)
from advanced_alchemy.types.file_object import storages
from advanced_alchemy.types.file_object.backends.obstore import ObstoreBackend
from app.lib.settings import get_settings


def register_storage_backends() -> None:
    s = get_settings().storage
    if storages.is_registered("uploads"):
        return
    if s.BACKEND == "s3":
        backend = ObstoreBackend(
            key="uploads",
            fs=f"s3://{s.BUCKET}/",
            aws_endpoint=s.ENDPOINT_URL or None,
            aws_access_key_id=s.ACCESS_KEY_ID,
            aws_secret_access_key=s.SECRET_ACCESS_KEY,
            aws_region=s.REGION,
            client_options={"allow_http": s.ALLOW_HTTP},
        )
    elif s.BACKEND == "local":
        backend = ObstoreBackend(key="uploads", fs=f"file://{s.LOCAL_PATH}")
    else:  # memory — tests
        from advanced_alchemy.types.file_object.backends.memory import InMemoryBackend
        backend = InMemoryBackend(key="uploads")
    storages.register_backend(backend)
```

(Exact `ObstoreBackend` constructor kwargs to be confirmed against the installed
advanced-alchemy version during implementation.)

### Wiring into app startup — `app/server/core.py` / `app/server/plugins.py`

Call `register_storage_backends()` from `ApplicationCore.on_app_init` (before
the SQLAlchemy plugin is used) so the `"uploads"` backend exists whenever a
`StoredObject` column is touched — by the web app **and** by the SAQ worker
(the worker uses the same `ApplicationCore` plugin). Add the call to the CLI
plugin path too so management commands work.

### `.env.local.example`

The storage block already exists but is commented out — uncomment it and align
the names with `StorageSettings` (`STORAGE_BACKEND=s3`, `AWS_ENDPOINT_URL=http://localhost:19000`,
`AWS_ACCESS_KEY_ID=app`, `AWS_SECRET_ACCESS_KEY=app`, `STORAGE_BUCKET=uploads`),
matching the dev rustfs service in `docker-compose.infra.yml`. Add a Makefile
note that `make start-infra` now also needs a one-time bucket creation (or add a
tiny `make create-bucket` target / extend the infra compose with a `storage-init`
like the prod stack has).

---

## Database

### `StoredObject` column type

Use `advanced_alchemy.types.file_object.StoredObject(backend="uploads")` as a
column type. It stores a JSON blob of `FileObject` metadata; the bytes are
uploaded to the object store on flush and deleted on row delete (advanced-alchemy
wires the session events).

### Models

**Phase A — generic attachments table** (`src/py/app/db/models/_attachment.py`):

| Column | Type | Description |
|---|---|---|
| `id` | `UUIDv7` | Primary key (`UUIDv7AuditBase`) |
| `uploaded_by_id` | `UUIDv7 FK` | `user_account.id` — who uploaded it |
| `team_id` | `UUIDv7 FK (nullable)` | Owning team, if any |
| `file` | `StoredObject("uploads")` | The stored file + metadata |
| `original_filename` | `String(255)` | As provided by the client |
| `content_type` | `String(255)` | Detected/declared MIME type |
| `size_bytes` | `BigInteger` | File size |
| `checksum_sha256` | `String(64) (nullable)` | Server-computed digest (integrity / dedup) |
| `purpose` | `Enum` | `attachment`, `avatar`, `team_logo`, `import`, `other` |
| `created_at` / `updated_at` | `DateTimeUTC` | Auto (from base) |

Add `__table_args__` index on `(uploaded_by_id,)` and `(team_id,)`.

**Phase B — concrete first uses (column references):**
- `User.avatar_id: Mapped[UUID | None]` FK → `attachment.id` (profile picture).
- `Team.logo_id: Mapped[UUID | None]` FK → `attachment.id`.
(Alternatively put a `StoredObject` column directly on `User`/`Team`; the
`Attachment` indirection is preferred so all uploads share one lifecycle, audit
trail, and admin view.)

### Migration

One Alembic migration: create `attachment`, add `avatar_id`/`logo_id` FK columns
to `user_account` and `team`. Place under `src/py/app/db/migrations/versions/`.

---

## Backend Structure

```
src/py/app/domain/attachments/
├── __init__.py
├── controllers/
│   ├── __init__.py
│   └── _attachment.py
├── services/
│   ├── __init__.py
│   └── _attachment.py
├── schemas/
│   ├── __init__.py
│   └── _attachment.py
├── deps.py
└── guards.py
```

Register the controller in `app/server/plugins.py` `domain` plugin (the same
place the other domain routers are wired).

### Schemas (`schemas/_attachment.py`)

```python
class Attachment(CamelizedBaseStruct):
    id: UUID
    original_filename: str
    content_type: str
    size_bytes: int
    purpose: str
    uploaded_by_id: UUID
    created_at: datetime
    download_url: str        # short-lived presigned URL (or app proxy URL)

class AttachmentUploadResponse(CamelizedBaseStruct):
    attachment: Attachment
```

Upload is `multipart/form-data` (Litestar `UploadFile`), not a struct — see
endpoints below.

### Service Logic (`services/_attachment.py`)

- `create_from_upload(data: UploadFile, *, user, team, purpose)`:
  1. Validate size (`STORAGE_MAX_UPLOAD_BYTES`) and content type
     (`STORAGE_ALLOWED_CONTENT_TYPES` if set) — sniff with `python-magic`-style
     check or trust the declared type minimally.
  2. Compute SHA-256 while streaming.
  3. Build `FileObject(content=..., filename=<uuid>/<safe-name>, ...)`, assign to
     `Attachment.file`, persist; advanced-alchemy uploads on flush.
  4. Return the `Attachment` with a presigned `download_url`
     (`attachment.file.sign(expires_in=STORAGE_PRESIGN_EXPIRY)` — confirm API).
- `get_download_url(attachment)`: presigned GET URL (preferred), or a path to an
  app endpoint that streams the object for backends that can't presign.
- `delete(attachment)`: delete the row; advanced-alchemy removes the object.
- `set_user_avatar(user, upload)` / `set_team_logo(team, upload)`: create an
  attachment with the right `purpose`, swap the FK, delete the previous one.

### API Endpoints

| Method | Path | Operation | Description |
|---|---|---|---|
| `POST` | `/api/uploads` | `UploadFile` | Upload a file (`multipart/form-data`; optional `?purpose=` and `?teamId=`). Returns `Attachment` with `downloadUrl`. |
| `GET` | `/api/uploads/{attachment_id}` | `GetUpload` | Returns `Attachment` metadata + fresh `downloadUrl`. |
| `GET` | `/api/uploads/{attachment_id}/content` | `DownloadUpload` | Streams the file through the app (fallback for non-presignable backends / when you want auth on every fetch). 302-redirects to a presigned URL when available. |
| `DELETE` | `/api/uploads/{attachment_id}` | `DeleteUpload` | Delete the file + row. |
| `PUT` | `/api/account/avatar` | `SetAvatar` | Upload & set the current user's avatar. |
| `DELETE` | `/api/account/avatar` | `ClearAvatar` | Remove the current user's avatar. |
| `PUT` | `/api/teams/{team_id}/logo` | `SetTeamLogo` | Upload & set a team logo (team-admin only). |

OpenAPI: mark the upload bodies as `RequestBody(media_type="multipart/form-data")`.
After endpoints land, run `make types` to regenerate the TS client.

### Guards (`guards.py`)

- `requires_attachment_access` — uploader, a member of the attachment's team, or
  superuser.
- Reuse existing team-admin guard for `PUT /api/teams/{id}/logo`.
- Rate-limit uploads (per-user) via existing middleware / a simple SAQ-backed
  counter if abuse is a concern.

---

## Frontend Structure

```
src/js/web/src/
├── components/uploads/
│   ├── file-upload.tsx          # drag-and-drop / picker, progress, validation
│   ├── avatar-uploader.tsx      # circular crop + upload, used in profile
│   └── attachment-chip.tsx      # filename + size + download/remove
├── lib/api/hooks/uploads.ts     # React Query mutations/queries
└── routes/_app/settings/profile.tsx   # wire avatar-uploader in
```

### React Query Hooks (`lib/api/hooks/uploads.ts`)

```typescript
useUploadFile()                 // POST /api/uploads (multipart, with progress)
useAttachment(id)               // GET  /api/uploads/:id
useDeleteAttachment(id)         // DELETE /api/uploads/:id
useSetAvatar()                  // PUT  /api/account/avatar
useClearAvatar()                // DELETE /api/account/avatar
useSetTeamLogo(teamId)          // PUT  /api/teams/:teamId/logo
```

### UI notes

- `file-upload.tsx`: client-side checks for size + accepted types before
  sending; show progress via `XMLHttpRequest`; show server validation errors.
- Avatar: show current avatar (from `user.avatar.downloadUrl`), allow replace /
  remove; optimistic update + invalidate the `me` query.
- Render images via the `downloadUrl` returned by the API; treat URLs as
  short-lived (re-fetch metadata if a 403 is hit).

---

## Testing

- `STORAGE_BACKEND=memory` (or `local` with a tmp dir) in the test settings so
  the suite needs no rustfs.
- Unit: `AttachmentService` create/delete round-trip; size & content-type
  rejection; checksum.
- Integration: `POST /api/uploads` happy path + oversize + bad type; download
  (presigned redirect and streamed fallback); avatar set/clear; team-logo
  permissions; deleting an attachment removes the object; deleting a user/team
  cascades attachment cleanup.
- A small CI smoke test that boots rustfs (compose) and exercises the S3 backend
  once, to catch obstore/rustfs incompatibilities.

---

## Operational Notes

- Prod & dev rustfs containers and the `uploads` bucket already exist (prod:
  `storage` + `storage-init` in `docker-compose.portainer.yml`; dev: `storage`
  in `docker-compose.infra.yml` — add a bucket-create step there if not present).
- Backups: the `storage-data` volume is already called out in
  `docs/deployment.md` §5. Once this feature is live, make sure that's actually
  being mirrored off-box.
- Lifecycle: consider a SAQ cron job to garbage-collect orphaned objects
  (objects in the bucket with no `attachment` row) and to enforce per-team
  storage quotas — punted to a later phase below.
- Switching to managed S3 later is just an env change (`AWS_ENDPOINT_URL` unset,
  real keys, `STORAGE_ALLOW_HTTP=false`) — no code change.

---

## Sub-Features & Tasks

### Phase 1: Storage plumbing (no user-visible change)
- [ ] Add `StorageSettings` to `app/lib/settings.py`; add to `Settings`
- [ ] Add `app/lib/storage.py` with `register_storage_backends()` (s3 / local / memory)
- [ ] Call it from `ApplicationCore.on_app_init` (web + worker + CLI paths)
- [ ] Uncomment/align the storage block in `.env.local.example`
- [ ] Add dev bucket-creation (Makefile target or `storage-init` in `docker-compose.infra.yml`)
- [ ] Smoke test: register backend, write + read a blob against dev rustfs

### Phase 2: Generic attachments + API
- [ ] `Attachment` model (`src/py/app/db/models/_attachment.py`)
- [ ] Alembic migration for `attachment`
- [ ] `domain/attachments/` — service, controller, schemas, deps, guards
- [ ] Endpoints: `POST/GET/DELETE /api/uploads`, `GET /api/uploads/{id}/content`
- [ ] Size / content-type validation; SHA-256 checksum
- [ ] Presigned download URLs (+ streamed fallback)
- [ ] Register router in `app/server/plugins.py`
- [ ] `make types`; tests (memory backend) + one rustfs integration test

### Phase 3: Avatars & team logos
- [ ] `User.avatar_id`, `Team.logo_id` FK columns + migration
- [ ] `PUT/DELETE /api/account/avatar`, `PUT /api/teams/{id}/logo`
- [ ] Include `avatar` / `logo` (with `downloadUrl`) in user/team read schemas
- [ ] `make types`
- [ ] Frontend: `file-upload.tsx`, `avatar-uploader.tsx`, `attachment-chip.tsx`
- [ ] Frontend: `lib/api/hooks/uploads.ts`
- [ ] Wire avatar uploader into profile settings; show team logo where relevant

### Phase 4: Hardening & lifecycle
- [ ] Per-user upload rate limiting
- [ ] SAQ cron: orphan-object garbage collection
- [ ] Per-team storage quota enforcement + admin visibility
- [ ] `/admin/attachments` management view (list, filter by team/purpose, delete)
- [ ] Audit-log entries for upload / delete

### Phase 5 (optional): Direct-to-S3 uploads
- [ ] `POST /api/uploads/presign` → presigned PUT URL + final `attachment` stub
- [ ] Client uploads straight to the bucket; `POST /api/uploads/{id}/complete`
      finalizes metadata (size/checksum) — removes large bodies from the app tier
