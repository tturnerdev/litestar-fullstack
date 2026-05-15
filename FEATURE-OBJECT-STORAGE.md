# Feature: Object Storage & File Uploads

## Summary

First-class file-upload / object-storage support is now wired into the
application using [`advanced-alchemy`](https://docs.advanced-alchemy.litestar.dev/)'s
`FileObject` / `StoredObject` integration backed by
[`obstore`](https://developmentseed.org/obstore/). Files live in an
S3-compatible object store; only lightweight metadata (filename, size, content
type, backend key, checksum) is persisted in PostgreSQL via a `StoredObject`
column type.

The production and dev **infrastructure** is provided by the companion
deployment work — see `docs/deployment.md` and
`tools/deploy/docker/docker-compose.portainer.yml` (prod, rustfs `storage`
service + `storage-init` bucket job) and
`tools/deploy/docker/docker-compose.infra.yml` (dev, rustfs `storage` service +
`storage-init`). The standard `AWS_*` / `STORAGE_*` environment variables are
wired into the `app` and `worker` containers.

> Status: **implemented on `claude/object-storage` (9 commits ahead of `main`).**
> Three validator agents reviewed the work and their high-impact findings have
> been addressed. Items intentionally not completed (concurrency-race-safe
> quotas, server-bound presigned-PUT size, etc.) are captured in
> `FEATURE-OBJECT-STORAGE-DEFERRED.md`.

---

## Dependencies

Already present in `pyproject.toml`: `advanced-alchemy[uuid,obstore,pwdlib]`
(the `obstore` extra pulls in `obstore` + advanced-alchemy's `ObstoreBackend`).
No new Python dependencies were added.

Frontend: no new dependencies. Multipart upload uses `XMLHttpRequest` for
upload-progress events (the generated `client` is `fetch`-based and cannot
expose `xhr.upload.onprogress`).

---

## Configuration

### `StorageSettings` — `app/lib/settings.py`

Added a `StorageSettings` dataclass (prefix `STORAGE_` plus the standard
`AWS_*` variables for the S3 backend) and added it to the composed `Settings`:

| Env var | Default | Description |
|---|---|---|
| `STORAGE_BACKEND` | `s3` | `s3` (obstore S3 — AWS / MinIO / RustFS), `local` (obstore local filesystem), `memory` (tests) |
| `STORAGE_BUCKET` | `uploads` | Bucket / container name |
| `AWS_ENDPOINT_URL` | _(unset)_ | S3 endpoint override; `http://storage:9000` in Docker, unset for real AWS |
| `AWS_ACCESS_KEY_ID` | _(unset)_ | S3 access key |
| `AWS_SECRET_ACCESS_KEY` | _(unset)_ | S3 secret key |
| `AWS_REGION` | `us-east-1` | S3 region |
| `STORAGE_ALLOW_HTTP` | `true` | Allow plain-HTTP S3 endpoints (needed for in-cluster rustfs) — set `false` for real AWS |
| `STORAGE_LOCAL_PATH` | _tempdir_/`litestar-uploads` | Filesystem root when `STORAGE_BACKEND=local` |
| `STORAGE_PRESIGN_EXPIRY` | `3600` | Seconds a presigned upload/download URL is valid |
| `STORAGE_MAX_UPLOAD_BYTES` | `26214400` (25 MiB) | Server-side upload size cap |
| `STORAGE_MAX_UPLOADS_PER_HOUR` | `0` (unlimited) | Per-user rolling-hour rate limit |
| `STORAGE_TEAM_QUOTA_BYTES` | `0` (unlimited) | Aggregate bytes per team |
| `STORAGE_ORPHAN_GC_GRACE_SECONDS` | `3600` | Grace window for the orphan-object SAQ job |

### Store registry — `app/lib/storage.py`

`register_storage_backends()` builds the configured `ObstoreBackend` (s3 /
local / memory) and registers it under `"uploads"` with advanced-alchemy's
global storage registry. It is idempotent and called from
`ApplicationCore.on_app_init` (web + worker) and `on_cli_init` (CLI / migrator).

### `.env.local.example`

The dev storage block is active and points at the local rustfs (`localhost:19000`,
credentials `app/app`). The `storage-init` service in `docker-compose.infra.yml`
creates the `uploads` bucket on `make start-infra`.

---

## Database

### `StoredObject` column type

Used via `advanced_alchemy.types.file_object.StoredObject(backend="uploads")`.
Stores a JSON blob of `FileObject` metadata; bytes live in the object store.

### Models

**`src/py/app/db/models/_attachment.py`**:

| Column | Type | Description |
|---|---|---|
| `id` | `UUIDv7` | Primary key (`UUIDv7AuditBase`) |
| `uploaded_by_id` | `UUIDv7 FK (nullable)` | `user_account.id`, `ON DELETE SET NULL` |
| `team_id` | `UUIDv7 FK (nullable)` | `team.id`, `ON DELETE CASCADE` |
| `file` | `StoredObject("uploads")` | Stored file metadata |
| `original_filename` | `String(255)` | Sanitized client filename |
| `content_type` | `String(255)` | MIME type |
| `size_bytes` | `BigInteger` | File size |
| `checksum_sha256` | `String(64) (nullable)` | Server-computed SHA-256 (null for presigned uploads) |
| `purpose` | `Enum` (str) | `attachment` / `avatar` / `team_logo` / `import` / `other` |
| `created_at` / `updated_at` | `DateTimeUTC` | Auto |

Indexes: `uploaded_by_id`, `team_id`, `purpose`.

**Extensions to existing models:**

- `User.avatar_id`: FK → `attachment.id`, `ON DELETE SET NULL`, `use_alter=True`
  (to break the circular FK with `attachment.uploaded_by_id` for `create_all`).
- `Team.logo_id` + `Team.logo_url`: FK + display-URL column.

### Migrations

Two migrations under `src/py/app/db/migrations/versions/`:

- `a1f3c2d4e5b6` — `add_attachment_table` (creates the `attachment` table + indexes + FKs).
- `b2e4d6f8a0c1` — `add_avatar_and_logo_attachments` (adds `user_account.avatar_id`,
  `team.logo_id`, `team.logo_url` + the SET NULL constraints).

---

## Backend Structure

```
src/py/app/domain/attachments/
├── __init__.py
├── deps.py          # provide_attachments_service
├── jobs.py          # cleanup_orphan_attachments (SAQ cron)
├── controllers.py   # AttachmentController
├── services/
│   ├── __init__.py
│   └── _attachment.py
└── schemas/
    ├── __init__.py
    └── _attachment.py
```

Auto-discovered by `DomainPlugin`; no explicit registration needed.

### Service highlights (`AttachmentService`)

- `create_from_upload` — reads the multipart `UploadFile`, enforces empty /
  size / rate / quota limits, computes SHA-256, builds a path namespaced by
  uploader (`{purpose}/{user_id}/{uuid7}-{safe_name}`), uploads, persists.
- `delete_with_object` — nulls dangling `User.avatar_url` /
  `Team.logo_url` first, deletes the row (cascade nulls `*_id`), then
  best-effort removes the stored object. Order matters: a row-delete failure
  no longer leaves an orphan object.
- `presign_upload` / `complete_upload` — direct-to-storage upload flow with
  uploader-namespaced paths; `/complete` rejects paths outside the caller's
  namespace, restricted purposes (`avatar`/`team_logo`), and any path
  containing `..` or a leading `/`.
- `cleanup_orphan_objects` — async iteration over the bucket; deletes objects
  with no `Attachment` row, respecting `STORAGE_ORPHAN_GC_GRACE_SECONDS`.

### API Endpoints

| Method | Path | Operation | Notes |
|---|---|---|---|
| `POST` | `/api/uploads` | `UploadFile` | multipart `data`; rejects `purpose=avatar/team_logo` |
| `GET` | `/api/uploads` | `ListUploads` | paginated; current user's; superusers see all |
| `GET` | `/api/uploads/{id}` | `GetUpload` | metadata + relative `downloadUrl` |
| `GET` | `/api/uploads/{id}/content` | `DownloadUpload` | streams bytes — forced `application/octet-stream` + `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff` for non-image content; inline for whitelisted image types on avatar/logo purposes |
| `DELETE` | `/api/uploads/{id}` | `DeleteUpload` | 204; emits `attachment.deleted` audit entry |
| `POST` | `/api/uploads/presign` | `PresignUpload` | returns `{uploadUrl, path, expiresIn}` for direct-to-S3 PUT |
| `POST` | `/api/uploads/complete` | `CompleteUpload` | HEADs object, validates size + quotas, records the row |
| `PUT` | `/api/me/avatar` | `AccountAvatarSet` | multipart `data` → 200 `User` (with `avatarUrl`) |
| `DELETE` | `/api/me/avatar` | `AccountAvatarClear` | 200 `User` |
| `PUT` | `/api/teams/{teamId}/logo` | `SetTeamLogo` | team-admin only; 200 `Team` (with `logoUrl`) |
| `GET` | `/api/admin/attachments` | `AdminListAttachments` | superuser; paginated |
| `DELETE` | `/api/admin/attachments/{id}` | `AdminDeleteAttachment` | superuser; emits audit entry |

### Audit logging

Wired via `AuditLogService.log_action`:

- `attachment.uploaded` / `attachment.deleted` (regular + admin paths, with `presigned: true` for `/complete`).
- `user.avatar.set` / `user.avatar.cleared`.
- `team.logo.set`.

### SAQ cron

`cleanup_orphan_attachments` registered at `0 3 * * *` (daily 03:00) in
`SaqSettings.get_config`.

### Access model

- Generic attachments: visible to the uploader or a superuser.
- Avatars and team logos: visible to **any authenticated user** (so the UI
  can render them inline).

---

## Frontend Structure

```
src/js/web/src/
├── components/uploads/
│   ├── file-upload.tsx          drag-and-drop picker, progress, validation
│   ├── avatar-uploader.tsx      current-avatar widget with replace / remove
│   └── attachment-chip.tsx      filename + size + download + remove
├── components/admin/
│   └── attachment-table.tsx     admin paginated table
├── lib/api/hooks/uploads.ts     TanStack Query hooks + helpers (camelCase types,
│                                XHR uploader for progress events)
└── routes/_app/
    ├── profile/index.tsx        AvatarUploader wired in
    └── admin/attachments.tsx    /admin/attachments page
```

### Hooks (`lib/api/hooks/uploads.ts`)

Hand-written against the API contract (the generated SDK does not yet include
these endpoints — see "Open follow-ups" below):

```typescript
useUploads({ page, pageSize })
useAttachment(id)
useUploadFile()                  // multipart with onProgress
useDeleteAttachment()
useSetAvatar()                   // multipart with onProgress
useClearAvatar()
useSetTeamLogo(teamId)           // multipart with onProgress
useAdminAttachments({ page, pageSize })

// helpers
downloadAttachment(att)
fetchAttachmentObjectUrl(att)
formatBytes(bytes)               // base-1024 (KiB/MiB/GiB)
MAX_UPLOAD_SIZE_BYTES            // mirrors the server limit
```

Authentication mirrors `main.tsx`'s `client.setConfig`: bearer token from
`localStorage`, `X-XSRF-TOKEN` from `window.__LITESTAR_CSRF__`,
`withCredentials = true`.

---

## Testing

- **`tests/unit/lib/test_storage.py`** — registration idempotency + a
  memory-backend save/read/delete round-trip.
- **`tests/unit/attachments/test_attachment_service.py`** — parametrized
  `_sanitize_filename` tests.
- **`tests/integration/attachments/routes/`** — 14 integration tests covering
  upload + get + download + list + delete; empty-file rejection; cross-user
  access (uploader + superuser, plus avatar global readability); avatar set
  / replace / clear; team-logo happy path; admin list / delete; presign
  unsupported-backend; `/complete` path-validation (cross-user, traversal,
  absolute); `/presign` restricted purposes; forced-attachment download
  headers.

Tests run with `STORAGE_BACKEND=memory` so no real object store is needed.

---

## Sub-Features & Tasks (completion status)

### Phase 1: Storage plumbing
- [x] Add `StorageSettings` to `app/lib/settings.py`; add to `Settings`
- [x] Add `app/lib/storage.py` with `register_storage_backends()` (s3 / local / memory)
- [x] Call it from `ApplicationCore.on_app_init` (web + worker + CLI paths)
- [x] Uncomment/align the storage block in `.env.local.example`
- [x] Add dev bucket-creation (`storage-init` in `docker-compose.infra.yml`)
- [x] Smoke test: register backend, write + read a blob against the memory backend

### Phase 2: Generic attachments + API
- [x] `Attachment` model (`src/py/app/db/models/_attachment.py`)
- [x] Alembic migration for `attachment`
- [x] `domain/attachments/` — service, controller, schemas, deps
- [x] Endpoints: `POST/GET/DELETE /api/uploads`, `GET /api/uploads/{id}/content`
- [x] Size / content-type validation; SHA-256 checksum; size limit; empty rejection
- [x] Relative download URLs (auth-on-every-fetch, backend-agnostic)
- [x] Auto-discovered by `DomainPlugin` (no manual router registration needed)
- [x] Tests (memory backend) — integration test for endpoints, unit tests for the sanitizer

### Phase 3: Avatars & team logos
- [x] `User.avatar_id`, `Team.logo_id` (+ `Team.logo_url`) FK columns + migration
- [x] `PUT/DELETE /api/me/avatar`, `PUT /api/teams/{id}/logo`
- [x] `avatarUrl` / `logoUrl` exposed in the User / Team read schemas
- [x] Frontend: `file-upload.tsx`, `avatar-uploader.tsx`, `attachment-chip.tsx`
- [x] Frontend: `lib/api/hooks/uploads.ts`
- [x] Wire avatar uploader into profile settings

### Phase 4: Hardening & lifecycle
- [x] Per-user upload rate limiting (`STORAGE_MAX_UPLOADS_PER_HOUR`, soft cap)
- [x] SAQ cron: orphan-object garbage collection (`cleanup_orphan_attachments`, daily 03:00)
- [x] Per-team storage quota enforcement (`STORAGE_TEAM_QUOTA_BYTES`, soft cap)
- [x] `/api/admin/attachments` management view + delete + frontend table
- [x] Audit-log entries for upload / delete / avatar / logo

### Phase 5: Direct-to-S3 uploads
- [x] `POST /api/uploads/presign` → presigned PUT URL + uploader-namespaced path
- [x] `POST /api/uploads/complete` — HEADs the object, validates path + size + quotas, records the row

---

## Notable deviations from the original plan

- **`downloadUrl` is a relative app-streamed URL**, not a presigned S3 URL.
  This works against every backend (including the in-memory test backend),
  carries auth on every fetch, and keeps URLs cacheable behind the reverse
  proxy. Presigned-direct downloads were intentionally punted to a later phase.
- **Avatars and team logos are publicly readable to authenticated users.**
  The original plan had them gated to the uploader/superuser only; that
  broke every UI surface that showed someone else's avatar. Auth is still
  required to fetch them; the bytes are not anonymous.
- **`/api/uploads`, `/api/uploads/presign`, `/api/uploads/complete` reject
  `purpose=avatar|team_logo`** — those must go through their dedicated
  endpoints. Without this, any user could create rows tagged as someone
  else's avatar / a team logo.
- **Presigned-upload paths are namespaced by uploader.** The path scheme is
  `{purpose}/{user_id}/{uuid7}-{safe_name}` and `/complete` validates the
  caller against that prefix.
- **`User.avatar_id` and `Team.logo_id` FKs use `use_alter=True`** to break
  the circular FK with `attachment.uploaded_by_id` / `attachment.team_id`
  when using `metadata.create_all` in tests.
- **No frontend dependency on regenerated SDK.** The `uploads.ts` hooks are
  hand-written against the contract because `make types` cannot run in the
  sandbox; once a developer regenerates `src/js/web/src/lib/generated/`,
  these hooks can be migrated onto the generated SDK (keeping the XHR helper
  for progress events).

---

## Operational Notes

- Prod & dev rustfs containers and the `uploads` bucket exist (prod:
  `storage` + `storage-init` in `docker-compose.portainer.yml`; dev: `storage`
  + `storage-init` in `docker-compose.infra.yml`).
- Backups: the `storage-data` volume is documented in `docs/deployment.md` §5
  — ensure it is mirrored off-box now that uploads are live.
- Switching to managed S3 later is an env change (`AWS_ENDPOINT_URL` unset,
  real keys, `STORAGE_ALLOW_HTTP=false`) — no code change.

## Open follow-ups

See **`FEATURE-OBJECT-STORAGE-DEFERRED.md`** for items intentionally not
completed in this work and the recommended next plan to tackle them.
