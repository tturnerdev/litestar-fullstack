# Production Deployment (Docker Compose / Portainer)

This document describes how this application is deployed to production as a
**Portainer Stack** (a `docker compose` deployment managed by Portainer), and
the procedures for **updates**, **backups**, and **restoring from a backup**
after data loss, hardware failure, or a broken container host.

> **Scope.** This is the production path only. Local development is unchanged —
> keep using `make start-infra` (infra only) or `make start-all-docker` (the
> all-in-one local stack). None of the files referenced here affect dev.

---

## 1. Architecture

The production stack (`tools/deploy/docker/docker-compose.portainer.yml`) runs
these containers:

| Service    | Image                                              | Role |
|------------|----------------------------------------------------|------|
| `db`       | `postgres`                                          | PostgreSQL — the only **stateful** service that must be backed up. |
| `cache`    | `valkey/valkey`                                      | Redis-compatible cache + SAQ broker. AOF-persisted; not backed up (treated as ephemeral). |
| `migrator` | `ghcr.io/tturnerdev/litestar-fullstack`             | One-shot `litestar database upgrade --no-prompt`. Runs **before** `app`/`worker`, then exits. Shows as `exited (0)` in Portainer — that is normal. |
| `app`      | `ghcr.io/tturnerdev/litestar-fullstack`             | Litestar ASGI application (HTTP). Sits behind your **external** reverse proxy, which terminates TLS. |
| `worker`   | `ghcr.io/tturnerdev/litestar-fullstack`             | SAQ background worker. Also runs the scheduled cron jobs (hourly auth-token cleanup; OAuth-token refresh every 15 min). |
| `backup`   | `prodrigestivill/postgres-backup-local`             | Scheduled `pg_dump` (gzipped) with daily/weekly/monthly retention into the `db-backups` volume. |
| `storage`  | `rustfs/rustfs` *(optional, commented out)*         | S3-compatible object storage for file uploads. Off by default — the app stores uploads on local disk unless you enable it. |

`app`, `worker`, and `migrator` all use the **same image**, differing only by
command and a few environment variables.

TLS / HTTPS is **not** handled here — an external reverse proxy already does TLS
termination. The stack only publishes the app's plain-HTTP port (`APP_PORT`,
default `8000`); point the proxy at it.

### Persistent state

Everything that matters lives in one of three places — nothing irreplaceable is
trapped inside a single Docker volume:

1. **Git** — the compose file and this runbook.
2. **Portainer** — the stack's environment variables (secrets). Keep a copy in a
   password manager / secrets store; losing `SECRET_KEY` invalidates all
   sessions and tokens.
3. **Off-box backups** — the PostgreSQL dumps from the `backup` service (and the
   uploads volume, if you use local-disk storage). A backup that only exists on
   the same machine does not survive hardware failure — copy it elsewhere
   (see [§5](#5-backups)).

---

## 2. Container images

The `app`/`worker`/`migrator` image is built from
`tools/deploy/docker/Dockerfile.distroless` and published to GHCR by the
`.github/workflows/release-images.yaml` workflow:

- push to `main` → `ghcr.io/tturnerdev/litestar-fullstack:main` and `:sha-<short>`
- git tag `vX.Y.Z` (or a GitHub release) → `:X.Y.Z`, `:X.Y`, and `:latest`

**Pin `APP_IMAGE_TAG` to a real release tag in production** (e.g. `v0.3.0`).
Avoid `:latest` so deploys are deterministic and rollbacks are trivial.

To make the image public (so the server can pull it without credentials), set
the GHCR package visibility to public once in the GitHub UI, or configure a pull
secret in Portainer (Registries → add `ghcr.io` with a PAT).

To build/push manually instead of via CI:

```bash
docker buildx build \
  --platform linux/amd64 \
  -f tools/deploy/docker/Dockerfile.distroless \
  -t ghcr.io/tturnerdev/litestar-fullstack:v0.3.0 \
  --push .
```

---

## 3. First-time deployment on Portainer

### 3.1 Prerequisites

- A host running Docker, managed by Portainer.
- DNS for your app domain pointing at your reverse proxy, with the proxy
  forwarding to `http://<docker-host>:<APP_PORT>`.
- The image published to GHCR (or your registry), and a pull secret configured
  in Portainer if the package is private.

### 3.2 Create the stack

In Portainer: **Stacks → Add stack**, then choose one of:

- **Git repository** (recommended): repository URL of this project, reference
  `refs/heads/prod` (see [§7](#7-branch-strateg)), compose path
  `tools/deploy/docker/docker-compose.portainer.yml`. Optionally enable
  **GitOps updates** (polling or webhook) so new commits/tags redeploy
  automatically.
- **Web editor**: paste the contents of
  `tools/deploy/docker/docker-compose.portainer.yml`.

### 3.3 Set environment variables

In the stack's **Environment variables** section, add the variables from
`tools/deploy/docker/.env.portainer.example`. The ones marked `[REQUIRED]` must
be set:

- `SECRET_KEY` — `openssl rand -hex 32`
- `APP_URL` — e.g. `https://app.example.com`
- `POSTGRES_PASSWORD` — a strong password
- `APP_IMAGE_TAG` — the release you are deploying, e.g. `v0.3.0`

Set `ALLOWED_CORS_ORIGINS` to your real origin, and configure email
(`EMAIL_BACKEND=smtp` + `EMAIL_SMTP_*`, or `EMAIL_BACKEND=resend` +
`RESEND_API_KEY`) if the app sends mail.

### 3.4 Deploy

Deploy the stack. Order of operations: `db` and `cache` become healthy →
`migrator` runs the migrations and exits 0 → `app` and `worker` start. The
`app` container has an HTTP health check on `/health`. Then verify through your
reverse proxy that the site responds.

---

## 4. Update procedure

1. Merge changes to `main`; tag a release `vX.Y.Z` → CI publishes
   `ghcr.io/tturnerdev/litestar-fullstack:vX.Y.Z`.
2. **Take a manual database backup first** (see [§5.2](#52-on-demand-backup)) —
   always, but especially when the release includes migrations.
3. Update `APP_IMAGE_TAG` to the new release in the Portainer stack's
   environment variables (or, if you track `prod` via GitOps, fast-forward
   `prod` to the release commit).
4. Redeploy the stack in Portainer (enable "re-pull image"). On redeploy:
   `migrator` runs `database upgrade` again (a no-op if there are no new
   migrations), then `app`/`worker` restart on the new image. If `migrator`
   fails, `app`/`worker` will not start — fix forward or roll back.
5. Confirm health: `app` container healthy, `/health` returns 200 through the
   proxy, worker logs show it connected.

**Rollback.** Set `APP_IMAGE_TAG` back to the previous release and redeploy. If
the bad release included a schema migration, a code-only rollback is not enough
— either run `litestar database downgrade` (see below) or restore the
pre-deploy backup ([§6](#6-restoring-from-a-backup)). Prefer backwards-compatible
("expand/contract") migrations so a code rollback is always safe on its own.

Run a one-off command in the stack (e.g. a manual downgrade) from Portainer's
console for the `app` container, or:

```bash
docker compose -f tools/deploy/docker/docker-compose.portainer.yml \
  run --rm app litestar database downgrade --no-prompt
```

---

## 5. Backups

### 5.1 What gets backed up

- **PostgreSQL** — the `backup` service runs `pg_dump` (plain SQL, gzipped, with
  `--clean --if-exists`) on `BACKUP_SCHEDULE` (default `@daily`) into the
  `db-backups` volume, keeping `BACKUP_KEEP_DAYS` / `WEEKS` / `MONTHS`
  generations. Files land under `daily/`, `weekly/`, `monthly/`, and the newest
  in `last/`.
- **Valkey** — not backed up. It is a cache + job broker; AOF persistence
  (`--appendonly yes`) is enough to survive a restart. Losing in-flight SAQ jobs
  is acceptable (the cron jobs re-run on schedule).
- **Uploaded files** — if you use the optional `storage` service, back up its
  bucket/volume separately (or use a managed S3 bucket). If you do not use it,
  the app writes uploads to local disk inside the `app` container — add a named
  volume for that path and back it up too, or move to object storage.
- **Configuration** — the compose file is in Git; the stack environment
  variables live in Portainer. Export/record them somewhere safe.

### 5.2 On-demand backup

Before any risky change:

```bash
# replace the project/stack name as shown in `docker ps`
docker exec <db-container> sh -c \
  'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists' \
  | gzip > backup-$(date +%F-%H%M%S).sql.gz
```

Or trigger the `backup` container's job immediately:

```bash
docker exec <backup-container> /backup.sh
```

### 5.3 Get backups off the box

A backup on the same host does not protect against hardware loss. Either:

- bind-mount a host directory into the `backup` service (`- /srv/litestar-backups:/backups`)
  and sync it off-site (`rclone`, `restic`, `aws s3 sync`, …) on a cron, or
- run a small sidecar that ships `db-backups` to remote object storage.

Periodically **test-restore** a backup into a throwaway stack — an untested
backup is not a backup.

---

## 6. Restoring from a backup

In all cases, restore an **uncompressed** dump with `psql` (dumps from the
`backup` service are plain SQL gzipped, made with `--clean --if-exists`, so they
drop and recreate objects as they go).

### 6.1 Data loss / corruption (database host intact)

```bash
# 1. stop the things that write to the database
docker compose -f tools/deploy/docker/docker-compose.portainer.yml stop app worker

# 2. restore (this drops & recreates objects thanks to --clean --if-exists)
gunzip -c /path/to/backup.sql.gz | \
  docker exec -i <db-container> psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"
# If the dump was NOT taken with --clean, instead reset the schema first:
#   docker exec -i <db-container> psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
#     -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'

# 3. bring everything back; `migrator` reconciles the schema, app/worker start
docker compose -f tools/deploy/docker/docker-compose.portainer.yml up -d
```

### 6.2 Hardware failure / migrating to a new host

1. Install Docker + Portainer on the new host.
2. Recreate the stack from Git with the **same environment variables** (restore
   them from your secrets store).
3. Let `db` initialise an empty data directory, then restore the latest off-box
   dump into it (as in §6.1, step 2). Restore the uploads volume from its
   backup if applicable.
4. `docker compose ... up -d` — `migrator` runs, `app`/`worker` start.
5. Repoint the reverse proxy / DNS at the new host.

### 6.3 Broken container system (Docker / Portainer corrupted)

- Reinstall Docker and Portainer. If the named volumes (`db-data`, `cache-data`,
  `db-backups`) survived, just recreate the stack — it reattaches them and comes
  back up.
- If the volumes are gone, treat it as §6.2 and restore from the off-box
  backups.

### 6.4 Sanity checks after any restore

- `migrator` exited 0; `app` is healthy; `/health` returns 200 via the proxy.
- Spot-check key data (user count, recent records).
- Confirm the `backup` service writes a fresh dump on its next scheduled run.

---

## 7. Branch strategy (`main` vs `prod`)

To keep the production configuration stable and obvious, deployments track a
dedicated **`prod`** branch:

- **`main`** — normal development. The production compose file
  (`docker-compose.portainer.yml`), this doc, and the image-publishing workflow
  live here too, because they do not conflict with the dev environment.
- **`prod`** — what Portainer deploys. Branched from `main`; kept as close to
  `main` as possible. **Only** changes that are required for production *and*
  would break local development if put on `main` belong here. (At present there
  are none, so `prod` simply tracks `main`.)

To ship: merge to `main`, tag a release, then fast-forward `prod` to that commit
(plus any prod-only overrides) and redeploy.
