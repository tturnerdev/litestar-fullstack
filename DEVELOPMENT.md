# Development Guide

Comprehensive guide for setting up, developing, testing, and contributing to the Admin Portal.

## Table of Contents

- [Prerequisites](#prerequisites)
- [First-Time Setup](#first-time-setup)
- [Daily Development](#daily-development)
- [Project Structure](#project-structure)
- [Architecture Patterns](#architecture-patterns)
- [Working with the API](#working-with-the-api)
- [Testing](#testing)
- [Linting & Formatting](#linting--formatting)
- [Database Migrations](#database-migrations)
- [Seed Data](#seed-data)
- [Error Tracking](#error-tracking)
- [Docker](#docker)
- [AI-Assisted Development](#ai-assisted-development)
- [Staging Deployment](#staging-deployment)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| **Docker** | Infrastructure containers (Postgres, Redis, etc.) | [docs.docker.com](https://docs.docker.com/get-docker/) |
| **uv** | Python package manager (fast pip/venv replacement) | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| **bun** | JavaScript runtime and package manager | `curl -fsSL https://bun.sh/install \| bash` |
| **overmind** (optional) | Process manager for running app + worker together | `brew install overmind` or [GitHub releases](https://github.com/DarthSim/overmind/releases) |

> `make dev-setup` will install `uv` and `bun` automatically if they're missing. Docker must be installed beforehand.

---

## First-Time Setup

```bash
git clone <repo-url>
cd admin-portal
make dev-setup
```

This single command:
1. Installs `uv` and `bun` if not already present
2. Creates `.env` from `.env.local.example` if it doesn't exist
3. Creates a Python virtual environment and installs all dependencies
4. Installs frontend (JS) dependencies via `bun install`
5. Starts infrastructure containers (PostgreSQL, Valkey/Redis, Mailpit, RustFS)
6. Waits for PostgreSQL to be healthy
7. Applies all database migrations

After setup completes, seed the database and start the server:

```bash
make seed     # Populate DB with sample data
make dev      # Start the app server — visit http://localhost:8000
```

Login with `admin@example.com` / `Test1234!@#$` (seeded superuser).

The frontend dev server (Vite) runs on port 3006 with hot module replacement. The backend proxies to it automatically when `VITE_DEV_MODE=true`.

---

## Daily Development

### Starting the App

```bash
# Option 1: App server only (most common)
make dev

# Option 2: App server + SAQ background worker
make dev-all

# Option 3: App server in debug mode
make dev-debug
```

`make dev-all` uses [overmind](https://github.com/DarthSim/overmind) to run both the Litestar app server and the SAQ worker concurrently. Output is color-coded by process name. If overmind is not installed, start them separately:

```bash
# Terminal 1
make dev

# Terminal 2
uv run litestar workers run
```

### Infrastructure

Infrastructure containers (Postgres, Redis, Mailpit, S3-compatible storage) must be running for the app to work:

```bash
make start-infra    # Start all infrastructure containers
make stop-infra     # Stop containers (preserves data)
make wipe-infra     # Stop containers AND delete all data
make infra-logs     # Tail container logs
```

Infrastructure services and their local ports:

| Service | Port | UI/Admin | Credentials |
|---------|------|----------|-------------|
| PostgreSQL | 15432 | — | `app` / `app` / `app` |
| Valkey (Redis) | 16379 | — | no auth |
| Mailpit (SMTP) | 11025 (SMTP), 18025 (Web) | http://localhost:18025 | — |
| RustFS (S3) | 19000 (API), 19001 (Console) | http://localhost:19001 | `app` / `app` |

### Environment Variables

Configuration is managed via `.env` (gitignored, created from `.env.local.example`):

```bash
# Key variables you may want to change:
LITESTAR_DEBUG=true          # Enable debug mode
LITESTAR_PORT=8000           # Backend port
VITE_DEV_MODE=true           # Enable Vite HMR proxy
VITE_PORT=3006               # Frontend dev server port
DATABASE_PORT=15432          # PostgreSQL port
```

See `.env.local.example` for the full list with documentation.

---

## Project Structure

```
admin-portal/
  src/
    py/
      app/
        db/
          models/            # SQLAlchemy models (one class per file)
          migrations/        # Alembic migrations
        domain/              # Business domains (auto-discovered)
          accounts/          # Auth, users, MFA, OAuth
          admin/             # Dashboard, audit logs, user management
          connections/       # External integration configs
          devices/           # Device provisioning and status
          e911/              # Emergency service registrations
          events/            # SSE real-time event streaming
          fax/               # Fax numbers, messages, email routing
          gateway/           # External API providers (FreePBX, Unifi, Telnyx)
          locations/         # Physical locations
          notifications/     # In-app notifications
          organizations/     # Org-level settings
          schedules/         # Time-based schedules
          support/           # Helpdesk tickets
          system/            # System jobs and health
          tags/              # Tagging system
          tasks/             # Background task management
          teams/             # Team management and RBAC
          voice/             # Phone numbers, extensions, voicemail
        lib/                 # Shared utilities, settings
        server/              # ASGI app factory, static assets
      tests/
        unit/                # Fast, isolated tests
        integration/         # Tests requiring database/services
        fixtures/
          wiremock/          # WireMock stubs for external API mocks
        conftest.py          # Shared fixtures (DB, app, factories)
        factories.py         # Polyfactory model factories
    js/
      web/
        src/
          components/        # Reusable UI components
          lib/
            api/
              hooks/         # React Query hooks (one file per domain)
            generated/       # Auto-generated API client (DO NOT EDIT)
          routes/
            _app/            # Authenticated routes (file-based routing)
      templates/             # React Email templates
  tools/
    deploy/
      docker/                # Dockerfiles and compose files
  AGENTS.md                  # AI assistant directives (universal)
  DEVELOPMENT.md             # This file
  FEATURE-*.md               # Feature specifications
  PROJECT.md                 # Architecture conventions
  Makefile                   # All dev/build/deploy commands
  Procfile.dev               # Process definitions for overmind
```

---

## Architecture Patterns

### Domain Structure

Each domain follows a consistent pattern. Using `devices` as the canonical example:

```
src/py/app/domain/devices/
  __init__.py              # Exports `routes = [DeviceController]`
  controllers/
    __init__.py
    _device.py             # Route handlers, DI via provide_service()
  services/
    __init__.py
    _device.py             # Business logic, inherits SQLAlchemyAsyncRepositoryService[Device]
  schemas/
    __init__.py
    _device.py             # Device, DeviceList, DeviceCreate, DeviceUpdate
  deps.py                  # create_service_dependencies(DeviceService, ...)
  guards.py                # require_active_team(), require_team_admin(), etc.
  listeners.py             # @listener("device_created") event handlers
  jobs.py                  # SAQ background tasks (reboot, provision, sync)
```

### Key Conventions

**Models** (`src/py/app/db/models/`):
- One class per file, prefixed with underscore: `_device.py`
- All models inherit `UUIDv7AuditBase` (UUIDv7 primary keys + `created_at`/`updated_at`)
- Exported from `__init__.py`

**Schemas** (`msgspec`):
- Use `CamelizedBaseStruct` for automatic camelCase serialization
- Separate types: `Device` (detail), `DeviceList` (list), `DeviceCreate`, `DeviceUpdate`
- Update schemas use `msgspec.UNSET` for optional partial updates

**Services**:
- Inherit `SQLAlchemyAsyncRepositoryService[Model]`
- Handle business logic, validation, and repository operations
- Injected via `create_service_dependencies()` in `deps.py`

**Controllers**:
- Route handlers decorated with `@get`, `@post`, `@patch`, `@delete`
- Use dependency injection for services and filters
- Guards for authorization

**Frontend Routes** (TanStack Router):
- File-based routing under `src/js/web/src/routes/_app/`
- `index.tsx` = list page, `new.tsx` = create, `$entityId.tsx` or `$entityId/index.tsx` = detail
- Use `createFileRoute()` with data loaders

**Frontend Hooks** (React Query):
- One file per domain in `src/js/web/src/lib/api/hooks/`
- Wraps auto-generated API client with React Query `useQuery`/`useMutation`
- Handles cache invalidation, optimistic updates

### External Integrations

All external service calls go through the **gateway** domain's provider pattern:

```
src/py/app/domain/gateway/
  providers/
    _freepbx.py      # FreePBX GraphQL API (OAuth2 + /admin/api/api/gql)
    _unifi.py         # Unifi REST API (/proxy/network/integration/v1/)
    _telnyx.py        # Telnyx REST API (/v2/phone_numbers, /v2/faxes)
```

Each provider is configured via a `Connection` model that stores host, port, credentials, and connection type.

---

## Working with the API

### After Backend Changes

Any time you modify a backend endpoint, schema, or controller, you **must** regenerate the frontend API client:

```bash
make types
```

This:
1. Starts the Litestar app temporarily to export the OpenAPI schema
2. Runs `@hey-api/openapi-ts` to generate TypeScript types and client at `src/js/web/src/lib/generated/`
3. The generated files should never be edited manually

Then verify the frontend compiles:

```bash
make tsc
```

### Adding a New Endpoint

1. Add/modify the controller method in `src/py/app/domain/<name>/controllers/`
2. Add/modify schemas in `src/py/app/domain/<name>/schemas/`
3. Run `make types`
4. Update/create React Query hooks in `src/js/web/src/lib/api/hooks/<name>.ts`
5. Update route components as needed
6. Run `make tsc` to verify TypeScript

---

## Testing

### Test Commands

```bash
make test              # Backend tests (pytest, parallel via xdist)
make test-unit         # Backend unit tests only
make test-frontend     # Frontend tests (vitest)
make test-all          # All backend + frontend tests
make test-integration  # Integration tests with isolated test infrastructure
make coverage          # Generate HTML/XML coverage reports
```

### Test Structure

```
src/py/tests/
  unit/                # Fast tests, no external dependencies
  integration/         # Tests requiring database, Redis, or external services
  conftest.py          # Session-scoped DB engine, app fixture, email setup
  data_fixtures.py     # Raw test data
  factories.py         # Polyfactory model factories
  fixtures/
    wiremock/           # WireMock stubs for external API mocking
```

### Test Markers

```python
@pytest.mark.unit           # Unit tests (fast, isolated)
@pytest.mark.integration    # Requires database/services
@pytest.mark.slow           # Long-running tests
@pytest.mark.external       # Requires external service access
@pytest.mark.auth           # Authentication-related
@pytest.mark.email          # Email-related
```

Run specific markers:

```bash
uv run pytest src/py/tests -m "unit"
uv run pytest src/py/tests -m "integration and not slow"
```

### Integration Test Infrastructure

For integration tests that need external service mocks, a completely isolated Docker stack is available:

```bash
make start-test-infra    # Start isolated test containers
make test-integration    # Start infra, run tests, stop infra (all-in-one)
make stop-test-infra     # Stop test containers
make wipe-test-infra     # Remove test containers and volumes
```

Test infrastructure runs on separate ports from development to avoid conflicts:

| Service | Dev Port | Test Port |
|---------|----------|-----------|
| PostgreSQL | 15432 | 25432 |
| Valkey (Redis) | 16379 | 26379 |
| Mailpit SMTP | 11025 | 21025 |
| Mailpit Web | 18025 | 28025 |
| RustFS (S3) | 19000 | 29000 |
| WireMock | — | 28080 |

The test Postgres uses `tmpfs` and disabled `fsync`/`synchronous_commit` for maximum speed.

Test environment variables are defined in `.env.test` (committed) — this file is automatically sourced by `make test-integration`.

### WireMock: External API Mocking

[WireMock](https://wiremock.org/) provides deterministic HTTP stubs for the three external providers (FreePBX, Unifi, Telnyx). Stubs are loaded from files at startup:

```
src/py/tests/fixtures/wiremock/
  mappings/                          # Request matching rules
    freepbx-token.json               # POST /admin/api/api/token
    freepbx-graphql.json             # POST /admin/api/api/gql
    unifi-sites.json                 # GET /proxy/network/integration/v1/sites
    unifi-clients.json               # GET .../sites/*/clients
    telnyx-phone-numbers.json        # GET /v2/phone_numbers
    telnyx-phone-number-messaging.json
  __files/                           # Response bodies
    freepbx/
      token_response.json
      all_extensions.json
    unifi/
      sites.json
      clients_site1.json
    telnyx/
      phone_numbers.json
      phone_number_messaging.json
```

**Adding a new stub:**

1. Create the response body JSON in `__files/<provider>/`
2. Create the mapping JSON in `mappings/` with request matching rules:

```json
{
  "request": {
    "method": "GET",
    "urlPath": "/api/endpoint"
  },
  "response": {
    "status": 200,
    "bodyFileName": "provider/response.json",
    "headers": { "Content-Type": "application/json" }
  }
}
```

3. Restart WireMock or use the admin API to reload: `curl -X POST http://localhost:28080/__admin/mappings/reset`

**Per-test overrides** — Use WireMock's Admin API to add high-priority stubs within a test, then reset:

```python
async def test_auth_failure(wiremock_url: str):
    async with httpx.AsyncClient() as client:
        # Override the default token stub with a 401
        await client.post(f"{wiremock_url}/__admin/mappings", json={
            "request": {"method": "POST", "urlPath": "/admin/api/api/token"},
            "response": {"status": 401, "jsonBody": {"error": "invalid_client"}},
            "priority": 1
        })
        # ... run test ...
        await client.post(f"{wiremock_url}/__admin/mappings/reset")
```

**WireMock Admin UI:** http://localhost:28080/__admin (when test infra is running)

---

## Linting & Formatting

```bash
make lint       # Run ALL linters
make fix        # Auto-format (ruff + biome)
make ruff       # Python linting + formatting only
make biome      # JavaScript/TypeScript linting only
make mypy       # Python type checking (mypy)
make pyright    # Python type checking (pyright)
make tsc        # TypeScript type checking
make codespell  # Spell checking
```

### Pre-Commit Hooks

Pre-commit hooks run automatically on `git commit`:

- **conventional-pre-commit** — Enforces conventional commit message format (`feat:`, `fix:`, `chore:`, etc.)
- **biome** — JS/TS formatting and linting
- **ruff** — Python linting and formatting
- **codespell** — Spell checking
- **check-ast, check-toml, trailing-whitespace, end-of-file-fixer** — Basic file hygiene

To run manually against all files:

```bash
make pre-commit
```

### Conventional Commits

All commit messages must follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(voice): add call queue management
fix(devices): handle null MAC address in provisioning
chore(deps): update litestar to 2.x
refactor(gateway): extract provider base class
docs: update development guide
```

### Branch Naming

Use a consistent prefix matching the conventional commit type:

```
feat/voice-call-queues        # New feature
fix/device-null-mac           # Bug fix
chore/update-dependencies     # Maintenance
refactor/gateway-providers    # Code restructuring
docs/development-guide        # Documentation
```

Keep names lowercase, hyphen-separated, and descriptive. Include the domain when relevant (e.g., `feat/voice-...`, `fix/devices-...`).

### Pre-Push Check

Run a quick validation before pushing (~15 seconds):

```bash
make check    # ruff + biome + tsc + unit tests
```

This catches most issues without the full CI overhead. For a comprehensive check:

```bash
make check-all    # All linting + all tests + coverage
```

---

## Database Migrations

```bash
make db-migrate m="add fax_messages table"   # Create a new migration
make db-upgrade                               # Apply pending migrations
make db-downgrade                             # Rollback one migration
make db-current                               # Show current revision
make db-history                               # Show migration history
```

Migrations are generated by Alembic and stored in `src/py/app/db/migrations/versions/`.

### Tips

- Always create a migration after modifying a SQLAlchemy model
- Review the generated migration before applying — Alembic's auto-detection isn't perfect
- Test migrations against a fresh database periodically (`make wipe-infra && make start-infra && make db-upgrade`)

---

## Seed Data

Populate the development database with realistic sample data:

```bash
make seed          # Idempotent — safe to run multiple times
make seed-reset    # Wipe all seed data and re-seed from scratch
```

### Seeded Entities

| Entity | Count | Notes |
|--------|-------|-------|
| Organization | 1 | "Acme Corp" |
| Team | 1 | "IT Department" |
| Users | 5 | Alice (superuser), Bob (admin), Carol, Dave, Erin |
| Locations | 2 | Main Office (SF), Branch Office (Oakland) |
| Phone Numbers | 5 | Local + toll-free |
| Extensions | 8 | Personal (100-104), Conference (200), Lobby (201), Branch (300) |
| Voicemail Boxes | 6 | With PINs, attached to personal extensions |
| Devices | 8 | Yealink, Poly desk phones, softphones, ATA — with line assignments |
| Fax Numbers | 3 | With email routes |
| Support Tickets | 5 | Open, in-progress, resolved, waiting, closed — with message threads |
| Tags | 6 | VIP, Remote, Conference Room, Lobby, IT Closet, Executive |
| Connections | 2 | FreePBX (PBX), Unifi (Network) with placeholder credentials |
| E911 Registrations | 3 | Tied to phone numbers and locations |
| Notifications | 4 | Mix of read/unread for admin user |

### Login Credentials

| Email | Password | Role |
|-------|----------|------|
| `admin@example.com` | `Test1234!@#$` | Superuser |

---

## Error Tracking

Error tracking is powered by [Sentry SDK](https://docs.sentry.io/) and compatible with both [Sentry](https://sentry.io/) and [GlitchTip](https://glitchtip.com/) (self-hosted, open-source alternative).

### Quick Setup (GlitchTip)

```bash
make start-glitchtip    # Start GlitchTip (http://localhost:18090)
```

1. Open http://localhost:18090 and create an account
2. Create an organization and a project (type: Python/Django works for Litestar)
3. Copy the DSN from the project settings
4. Add to your `.env`:

```bash
SENTRY_ENABLED=true
SENTRY_DSN=http://<key>@localhost:18090/1
VITE_SENTRY_DSN=http://<key>@localhost:18090/1
```

5. Restart the app — errors will now appear in the GlitchTip dashboard

### How It Works

**Backend** — `sentry-sdk[litestar]` initializes in `create_app()` before the Litestar app is constructed. Integrations: `LitestarIntegration` (request context, breadcrumbs), `SqlalchemyIntegration` (query tracking). `send_default_pii=False` by default.

**Frontend** — `@sentry/react` initializes in `main.tsx` before React renders. Both error boundary components (`RootErrorBoundary` and the TanStack Router `ErrorBoundary`) call `Sentry.captureException()`.

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTRY_ENABLED` | `false` | Enable/disable error tracking |
| `SENTRY_DSN` | — | Backend DSN (from GlitchTip/Sentry project settings) |
| `SENTRY_ENVIRONMENT` | `development` | Environment tag for filtering |
| `SENTRY_TRACES_SAMPLE_RATE` | `0.1` | % of requests to trace (0.0-1.0) |
| `SENTRY_PROFILES_SAMPLE_RATE` | `0.1` | % of traces to profile (0.0-1.0) |
| `VITE_SENTRY_DSN` | — | Frontend DSN (same DSN, prefixed with `VITE_` for Vite) |
| `VITE_SENTRY_ENVIRONMENT` | `development` | Frontend environment tag |

### GlitchTip Management

```bash
make start-glitchtip    # Start (http://localhost:18090)
make stop-glitchtip     # Stop
make wipe-glitchtip     # Remove with all data
```

### Migrating to Sentry

GlitchTip uses the standard Sentry SDK. To switch to Sentry (self-hosted or cloud), change only the DSN URLs — no code changes needed.

---

## Docker

### Infrastructure Only (Development)

```bash
make start-infra        # Postgres, Redis, Mailpit, RustFS
make stop-infra
make wipe-infra         # Deletes all data volumes
```

### Full Stack — Production (Distroless)

```bash
make start-all-docker   # Build and start production containers
make stop-all-docker
make docker-logs
```

### Full Stack — Development (Hot-Reload)

```bash
make start-all-docker-dev   # Build and start with Dockerfile.dev
make stop-all-docker-dev
make docker-dev-logs
make docker-shell           # Open shell in app container
```

---

## AI-Assisted Development

The project includes configuration for AI coding assistants.

### AGENTS.md

`AGENTS.md` is the universal AI directive file read by Claude Code, GitHub Copilot, Cursor, Windsurf, and 60+ other tools. It contains project context, architecture patterns, build commands, and coding conventions.

`CLAUDE.md` is a symlink to `AGENTS.md` (gitignored) — Claude Code reads it automatically at conversation start.

### Claude Code Skills

Three custom skills are available as slash commands in Claude Code:

| Command | Description |
|---------|-------------|
| `/new-domain <name>` | Scaffold a complete new domain (backend + frontend + migration) |
| `/fix-issue <number>` | Fetch a GitHub issue, find relevant code, fix, test, and commit |
| `/api-change <desc>` | Run the post-API-change checklist (types, tsc, tests) |

### Project Settings

`.claude/settings.json` contains shared project-level permissions for Claude Code, reducing permission prompts for common dev commands (`make`, `uv run`, `bun`, `git`, `docker compose`).

Personal settings go in `.claude/settings.local.json` (gitignored).

---

## Staging Deployment

The staging environment runs on a self-hosted server managed by Portainer. Every push to `main` triggers a GitHub Actions workflow that builds a Docker image, pushes it to GitHub Container Registry (GHCR), and signals Portainer to redeploy.

### How It Works

```
push to main
  -> GitHub Actions builds Dockerfile.distroless
  -> pushes to ghcr.io/<org>/<repo>:staging-latest
  -> pushes to ghcr.io/<org>/<repo>:staging-<sha>
  -> POST to Portainer webhook
  -> Portainer pulls staging-latest and redeploys the stack
```

### Image Tags

Each build produces two tags:

| Tag | Purpose |
|-----|---------|
| `staging-latest` | Always points to the most recent main build. Portainer pulls this on webhook trigger. |
| `staging-<sha>` | Pinned to a specific commit (short SHA). Use this to roll back to a known-good build. |

### Setup

#### 1. GitHub Actions Secrets

Only one secret is required. Go to **Settings > Secrets and variables > Actions** in the GitHub repo:

| Secret | Description |
|--------|-------------|
| `PORTAINER_STAGING_WEBHOOK_URL` | The webhook URL from the Portainer stack (see step 3 below) |

The `GITHUB_TOKEN` is automatically available with `packages:write` scope -- no additional token setup is needed for GHCR.

#### 2. Create the Portainer Stack

1. In Portainer, go to **Stacks > Add stack**
2. Choose **Repository** or **Web editor**
   - If **Repository**: point to this repo, set the compose path to `tools/deploy/docker/docker-compose.staging.yml`
   - If **Web editor**: paste the contents of `tools/deploy/docker/docker-compose.staging.yml`
3. Under **Environment variables**, add all variables from `tools/deploy/docker/.env.staging.example`
   - At minimum, set `GITHUB_REPO` (e.g. `your-org/admin-portal`) and `SECRET_KEY` (generate with `openssl rand -hex 32`)
4. Deploy the stack

#### 3. Configure the Portainer Webhook

1. After the stack is running, go to the stack settings in Portainer
2. Enable **Webhook** and copy the generated URL
3. Add this URL as the `PORTAINER_STAGING_WEBHOOK_URL` secret in GitHub Actions (step 1)

#### 4. GHCR Visibility (Private Repos)

If the repository is private, the container images in GHCR will also be private. Ensure the Portainer host can authenticate to GHCR:

1. In Portainer, go to **Registries > Add registry**
2. Select **Custom registry**, set URL to `ghcr.io`
3. Use a GitHub Personal Access Token (classic) with `read:packages` scope as the password

### Manual Deployment

To trigger a staging deployment without pushing to main, use the GitHub Actions UI:

1. Go to **Actions > Deploy to Staging**
2. Click **Run workflow**
3. Select the branch (defaults to `main`)

Or from the command line:

```bash
gh workflow run deploy-staging.yaml
```

### Rolling Back

To roll back to a previous build, update the image tag in Portainer:

1. Find the desired commit SHA in GHCR or `git log --oneline main`
2. In Portainer, edit the stack environment and change the image tags from `staging-latest` to `staging-<sha>` (or override the compose directly)
3. Redeploy the stack

Alternatively, revert the commit on `main` and let the pipeline redeploy automatically.

### Files

| File | Purpose |
|------|---------|
| `.github/workflows/deploy-staging.yaml` | CI/CD workflow: build, push to GHCR, trigger Portainer |
| `tools/deploy/docker/docker-compose.staging.yml` | Compose stack deployed to Portainer |
| `tools/deploy/docker/.env.staging.example` | Template for staging environment variables |

---

## Troubleshooting

### "Database connection refused"

Infrastructure containers probably aren't running:

```bash
make start-infra
docker ps    # Verify containers are up
```

### "Port already in use"

Another instance may be running. Check and stop it:

```bash
docker ps -a    # Check for leftover containers
make stop-infra
make start-infra
```

### "Generated types are stale"

If the frontend shows type errors after backend changes:

```bash
make types    # Regenerate the API client
make tsc      # Verify it compiles
```

### "Pre-commit hook failed"

Fix the issues reported, then try again:

```bash
make fix      # Auto-format
make lint     # Check what's still broken
git add -A && git commit
```

### "Tests fail with missing tables"

Database schema may be out of date:

```bash
make db-upgrade
```

### Fresh start

If everything is broken, reset completely:

```bash
make wipe-infra    # Delete all data
make destroy       # Delete Python venv
make dev-setup     # Rebuild everything from scratch
make seed          # Re-populate sample data
```
