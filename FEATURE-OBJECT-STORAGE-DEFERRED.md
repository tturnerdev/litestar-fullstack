# Object Storage — Deferred Work

This document captures items from the Object Storage feature
(`FEATURE-OBJECT-STORAGE.md`) and from the validator-agent reviews that were
intentionally not completed in the initial implementation on
`claude/object-storage`. Each item is recorded with enough context to pick up
later without re-running the discovery work.

---

## Summary

The implementation on `claude/object-storage` covers all five phases of the
original plan and addresses the high-severity findings from the security,
backend-correctness, and frontend reviews. The items below are the residue
— a mix of (a) defense-in-depth hardening that needs heavier-weight
infrastructure changes than the initial work, (b) UI polish that could not be
verified without a running dev server, and (c) build-pipeline tasks (TS
codegen) that need network access from a developer machine. None of the items
listed here are blockers for shipping the feature behind a feature flag or to
an internal-only audience; each is a real follow-up.

---

## Deferred items

### 1. Concurrency-race-safe rate limit and team quota

**Where**: `src/py/app/domain/attachments/services/_attachment.py` —
`AttachmentService._enforce_upload_quotas`.

**What's there now**: a plain `SELECT count(*)` for the per-user rate limit
and `SELECT sum(size_bytes)` for the team quota, evaluated before insert at
the default Postgres `READ COMMITTED` isolation level.

**Risk**: under burst load, N parallel uploads from the same user (or against
the same team) can each see the pre-burst totals and all pass. The limits are
therefore soft caps that prevent a leisurely abuse pattern but do not prevent
a co-ordinated burst.

**Why deferred**: the fix is non-trivial — needs either
`SELECT … FOR UPDATE` against a per-user / per-team row in a serializable
transaction, a Postgres advisory lock keyed on `uploaded_by_id` / `team_id`,
or a separate "reservation" table with a unique constraint, plus the
matching test infrastructure that exercises concurrent requests. This is a
hardening pass, not a correctness fix.

**Acceptance criteria for a follow-up**:
- The soft-cap behavior is documented (or removed in favor of the hard check).
- A test fires N concurrent uploads at a user with `MAX_UPLOADS_PER_HOUR=1`
  and asserts exactly one succeeds.
- The same for `TEAM_QUOTA_BYTES` at the boundary.

---

### 2. Server-bound size limit on the presigned PUT itself

**Where**: `AttachmentService.presign_upload` /
`AttachmentService.complete_upload`.

**What's there now**: `MAX_UPLOAD_BYTES` is enforced at multipart upload time
and **after** the presigned PUT lands (the server HEADs the object in
`/complete` and rejects + deletes if oversize). The presigned URL itself does
not bind a size.

**Risk**: a client can PUT 10 GiB at the presigned URL. The bucket eats the
bandwidth (and possibly storage cost) until `/complete` rejects and the
object is deleted; the bytes never become a row.

**Why deferred**: requires moving from `PUT` presigning to S3 POST-policy
(which supports `content-length-range`) or signing a `Content-Length` /
`x-amz-decoded-content-length` header. `obstore.sign` does not currently
expose those parameters; this likely needs either a custom signing path or
an upgrade to a newer obstore. There are also user-experience implications
(the frontend's XHR upload helper has to switch from a single `PUT` to a
form-based POST).

**Acceptance criteria for a follow-up**:
- The presigned URL rejects requests larger than `MAX_UPLOAD_BYTES` at the
  storage edge (4xx from S3 / rustfs, not from the app).
- `complete_upload` HEAD-time size check stays as a defense-in-depth net.
- The frontend's `uploadWithProgress` is updated to use whatever request
  shape the new signature requires.

---

### 3. Per-user storage quota

**Where**: `src/py/app/lib/settings.py` — `StorageSettings`.

**What's there now**: per-team quota only (`TEAM_QUOTA_BYTES`). A regular
user with no team can accumulate up to
`MAX_UPLOADS_PER_HOUR × MAX_UPLOAD_BYTES` per hour indefinitely.

**Why deferred**: cleanly setting an aggregate-bytes-per-user cap requires
the same concurrency story as item 1 (a `SELECT sum` race), plus a UX
decision on what the user sees when they hit the cap.

**Acceptance criteria for a follow-up**:
- A new `STORAGE_USER_QUOTA_BYTES` setting with `0 = unlimited`.
- Enforced in `_enforce_upload_quotas` (shares whatever locking strategy
  lands for items 1 and 2).
- Surfaced in the admin attachments view as a column or filter.

---

### 4. Replace `window.confirm` in the admin attachments table

**Where**:
`src/js/web/src/components/admin/attachment-table.tsx` —
`handleDelete`.

**What's there now**: `window.confirm("Delete …?")` blocks the main thread
and is not styleable or accessible to screen readers.

**Why deferred**: the codebase has a shadcn `AlertDialog` available, but
swapping it in is a small UI change that cannot be visually verified in this
sandbox (no dev server, no `bun install`). Punting until someone can render
the page.

**Acceptance criteria for a follow-up**:
- Confirmation is rendered via the codebase's `AlertDialog`.
- A destructive-variant button confirms.
- The previously-focused row receives focus back on dialog close.

---

### 5. Wire silent token refresh into the XHR uploader

**Where**:
`src/js/web/src/lib/api/hooks/uploads.ts` — `uploadWithProgress`.

**What's there now**: bearer token, CSRF header, and `withCredentials` are
plumbed manually to match the generated `client`'s configuration. The
silent-refresh interceptor in `main.tsx` (which transparently refreshes the
access token on 401 and retries the request) is **not** wired into the XHR
helper.

**Risk**: a long-running upload that crosses an access-token expiry boundary
fails with 401 even though the user is still logged in. Users see "upload
failed" and have to retry.

**Why deferred**: porting the refresh-and-retry logic to XHR is awkward
(reading the request body twice, re-establishing progress callbacks); also
needs verification with an actual long upload, which the sandbox can't do.

**Acceptance criteria for a follow-up**:
- On 401 from the upload XHR, the helper hits the refresh endpoint and
  retries once with the new token.
- A distinct "session expired" toast surfaces if the refresh itself fails.
- Progress callbacks fire correctly across the retry.

---

### 6. Migrate hand-written `uploads.ts` onto the regenerated SDK

**Where**: `src/js/web/src/lib/api/hooks/uploads.ts` and
`src/js/web/src/lib/generated/`.

**What's there now**: the hand-written hooks call the new endpoints directly
via the generated `client.get`/`client.delete`/`client.post` (for non-progress
calls) or the local `uploadWithProgress` helper (for multipart). The
generated SDK does **not** include `uploads.*`, `me.avatar.*`,
`teams.byId.logo.*`, or `admin.attachments.*` because `make types` cannot run
in the sandbox (the `litestar-vite-typegen` npm package is unreachable).

**Why deferred**: needs a developer to run `make types` with network access.
Until that happens, the hand-written hooks remain.

**Acceptance criteria for a follow-up**:
- A developer runs `make types` and commits the regen.
- The non-progress hooks (`useUploads`, `useAttachment`, `useDeleteAttachment`,
  `useClearAvatar`, `useAdminAttachments`) move onto the generated SDK + its
  `…QueryKey()` helpers, matching the rest of the codebase.
- The multipart-with-progress paths (`useUploadFile`, `useSetAvatar`,
  `useSetTeamLogo`) keep `uploadWithProgress`.

---

### 7. Replace hand edits to `routeTree.gen.ts`

**Where**: `src/js/web/src/routeTree.gen.ts`.

**What's there now**: the new `/admin/attachments` route is registered in
seven places in the "do not edit" generated file (import, `update()` call,
the three `FileRoutesBy*` maps, the union types, the module declaration, and
`AppAdminRouteChildren`). The edits mirror what the TanStack Router code
generator would emit.

**Why deferred**: the TanStack Router code generator regenerates this file on
dev-server start. The hand edits will be replaced cleanly the next time a
developer runs the generator, but until then the file is technically
"manually edited" generated code.

**Acceptance criteria for a follow-up**:
- A developer runs the TanStack Router generator (typically on dev-server
  start) and confirms the diff is a no-op.

---

### 8. Stream the download instead of buffering it in memory

**Where**:
`src/py/app/domain/attachments/services/_attachment.py` —
`AttachmentService.get_content` (used by the download endpoint).

**What's there now**: the entire object is read into memory with
`await attachment.file.get_content_async()` and then served as a single
`Response[bytes]`. Fine for typical attachment sizes (the limit is 25 MiB),
but defeats the streaming benefits of object storage if `MAX_UPLOAD_BYTES`
is raised.

**Why deferred**: switching to a streaming response involves a
`StreamingResponse` (Litestar's `Stream`) sourced from
`obstore.get_async(store, path).stream()` (or similar), plus careful
content-length / content-range handling for range requests. Not strictly
required at the current size cap.

**Acceptance criteria for a follow-up**:
- `GET /api/uploads/{id}/content` streams chunks from the backend without
  buffering the whole object.
- Range requests are correctly handled (or explicitly rejected with `416`).

---

### 9. Composite indexes for the quota / rate-limit queries

**Where**: `src/py/app/db/migrations/versions/` (and the `Attachment` model).

**What's there now**: single-column indexes on `uploaded_by_id`, `team_id`,
and `purpose`. The quota query (`SUM(size_bytes) WHERE team_id = ?`) and the
rate-limit query (`COUNT WHERE uploaded_by_id = ? AND created_at >= ?`) will
benefit from composite covering indexes at scale.

**Why deferred**: premature optimization at the row counts currently expected
(small reference application). Worth adding before any high-volume
deployment.

**Acceptance criteria for a follow-up**:
- A new migration adds `(uploaded_by_id, created_at)` and
  `(team_id) INCLUDE (size_bytes)` (or equivalent partial indexes).
- A simple `EXPLAIN` confirms index-only scans for the quota queries.

---

### 10. Image safety: strip metadata / validate real image bytes

**Where**: `AttachmentService.create_from_upload` (for `AVATAR` /
`TEAM_LOGO` purposes).

**What's there now**: server trusts the client-declared `content_type`. The
download endpoint forces `application/octet-stream` for unsafe types and
allows only a whitelist of image MIMEs for inline serving, plus
`X-Content-Type-Options: nosniff`. SVG is explicitly excluded.

**Risk**: a user can upload `evil.exe` with `Content-Type: image/png` and
have a row tagged as an avatar with that content type. The download
endpoint still serves it inline as `image/png` because the whitelist matches
— the browser will fail to render it (it's not really PNG), but the row's
metadata is wrong.

**Why deferred**: real image validation needs Pillow (already a dep), and
ideally re-encoding the image through Pillow so it strips EXIF / orientation
/ embedded scripts and proves the bytes are a real image. Adds noticeable
complexity to the upload path; better as a follow-up.

**Acceptance criteria for a follow-up**:
- Avatars and team logos are decoded with Pillow on upload; non-images are
  rejected with `415 Unsupported Media Type`.
- The server re-saves the image (stripping metadata) before persisting.
- EXIF / orientation is normalized.

---

## Next Steps — recommended follow-up plan

A future planning doc (call it `FEATURE-OBJECT-STORAGE-HARDENING.md`) could
take the items above and group them into shippable phases. A reasonable
breakdown:

### Phase A — Concurrency hardening (items 1 + 3)

Goal: turn the rate limit and quotas from soft caps into hard guarantees,
and add a per-user quota.

- Decide on a locking strategy: serializable txn with retry, advisory lock,
  or a dedicated `storage_usage` reservation table.
- Implement once and re-use for per-user rate limit, per-user quota, and
  per-team quota.
- Add `STORAGE_USER_QUOTA_BYTES` setting.
- Concurrency test that fires N parallel uploads at each boundary.

### Phase B — Direct-to-S3 size binding (item 2)

Goal: oversize PUTs are rejected by the storage layer, not the app.

- Move presign from PUT signing to S3 POST-policy with
  `content-length-range`, or attach a signed `Content-Length` to the PUT
  signature.
- Verify against real AWS S3 and rustfs.
- Update the frontend uploader to use the new shape.
- Keep the HEAD-time check as defense-in-depth.

### Phase C — Streaming downloads + indexes (items 8 + 9)

Goal: ready to scale.

- Stream from `obstore` into a Litestar `Stream` response.
- Range-request support (or explicit `416`).
- Composite indexes for quota / rate-limit queries.

### Phase D — Image validation pipeline (item 10)

Goal: avatars and team logos are real, re-encoded images.

- Pillow-based content sniffing + re-encoding for `AVATAR` /
  `TEAM_LOGO` purposes.
- EXIF / orientation normalization.
- 415 on non-images for those purposes.

### Phase E — Frontend polish (items 4 + 5 + 6 + 7)

Goal: clean up the unverified parts of the initial frontend work.

- Run `make types` on a network-capable machine; migrate hooks onto the
  regenerated SDK; commit the regen.
- Re-run TanStack Router codegen to replace the hand edits in
  `routeTree.gen.ts`.
- Replace `window.confirm` with `AlertDialog`.
- Wire silent token refresh into the XHR uploader; add a distinct
  "session expired" toast.
- Manual QA pass with the dev server: drag-and-drop hover states, progress
  bar visuals, avatar fallback contrast, admin table loading / error /
  empty states.

Each phase is independently shippable and any of them can be picked up first.
Phase A is the most security-relevant; Phase E is the most user-visible.
