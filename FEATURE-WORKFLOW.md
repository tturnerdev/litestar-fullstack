# FEATURE: DevOps Development Workflow

> Comprehensive development workflow covering AI-assisted development tooling, isolated development environments, and self-contained integration testing with mock external services.

## Status: Implemented

| Component | Status | Key Files |
|-----------|--------|-----------|
| AI directive files | Done | `AGENTS.md`, `.claude/settings.json`, `.claude/skills/` |
| Dev environment streamlining | Done | `Makefile` (`dev-setup`, `dev-all`), `Procfile.dev` |
| Test infrastructure | Done | `docker-compose.test.yml`, WireMock stubs, `.env.test` |
| CI integration | Done | `.github/workflows/ci.yaml` (test infra + frontend job) |
| Error tracking (GlitchTip) | Done | `sentry-sdk`, `@sentry/react`, `docker-compose.glitchtip.yml` |
| Seed data | Done | `src/py/app/cli/seed.py`, `make seed` |
| Pre-push check | Done | `make check` |
| Dependabot auto-merge | Done | `dependabot.yaml`, `dependabot-auto-merge.yaml` |
| PR template | Done | `.github/pull_request_template.md` |
| Branch naming convention | Done | Documented in `DEVELOPMENT.md` |
| Staging deployment | Done | `deploy-staging.yaml`, `docker-compose.staging.yml` |

---

## 1. AI-Assisted Development Tooling

### Problem

No structured AI-assistant configuration existed. Claude Code, Copilot, Cursor, and other tools had no project context, leading to repeated explanations of architecture, conventions, and commands.

### Solution

#### AGENTS.md (Universal, Committed)

`AGENTS.md` is the canonical AI directive file, following the [open standard](https://agents.md/) supported by 60+ tools (GitHub Copilot, Cursor, Windsurf, Google Jules, OpenAI Codex, Claude Code, etc.).

Contents:
- Build & run commands (make targets, tool versions)
- Architecture overview (backend/frontend structure, key patterns)
- Domain pattern (how to add new domains end-to-end)
- Code style conventions (file naming, schema types, guards, events)
- Important rules (when to run `make types`, generated file policy)
- Testing structure and markers
- External integration details

#### CLAUDE.md (Symlink, Gitignored)

`CLAUDE.md` is a symlink to `AGENTS.md`. Claude Code reads this automatically at conversation start. The symlink approach means a single source of truth with no sync overhead.

```
CLAUDE.md -> AGENTS.md
```

#### .claude/settings.json (Project Permissions, Committed)

Shared project-level permissions that reduce permission prompts for the whole team:

```json
{
  "permissions": {
    "allow": ["Bash(make *)", "Bash(uv run *)", "Bash(bun *)", "Bash(git status*)", ...],
    "deny": ["Bash(rm -rf /)*", "Bash(git push --force*)", ...]
  }
}
```

User-specific overrides remain in `.claude/settings.local.json` (gitignored).

#### .claude/skills/ (Workflow Automation, Committed)

Three custom skills for common workflows:

| Skill | Trigger | What it does |
|-------|---------|-------------|
| `/new-domain <name>` | Scaffolding | Creates full domain (backend + frontend + migration + hooks) |
| `/fix-issue <number>` | Bug fixes | Fetches GH issue, finds code, fixes, tests, commits |
| `/api-change <description>` | Post-API change | Runs `make types`, checks TS, updates hooks, runs tests |

#### .gitignore Changes

```gitignore
# .claude/ — track project settings and skills, ignore user-local state
.claude/*
!.claude/settings.json
!.claude/skills/
```

### Decision: AGENTS.md vs Tool-Specific Files

We chose AGENTS.md over maintaining separate `.cursorrules`, `.github/copilot-instructions.md`, etc. because:
- One file to maintain, works across 60+ tools
- Tools that don't read AGENTS.md natively can use symlinks (like our CLAUDE.md approach)
- Content is nearly identical across tools — the 5% difference isn't worth the maintenance cost

---

## 2. Isolated Development Environment

### Problem

Setting up the dev environment required 5+ manual steps: install uv, install bun, run `make install`, start Docker infra, start the app server. New feature branches or patches required remembering this sequence.

### Approach Evaluation

| Approach | Setup Time | Hot-Reload | WSL2 Perf | Claude Code Compat |
|----------|-----------|------------|-----------|-------------------|
| **Dev Containers** | 60-90s build | Port-forwarded HMR | Bind mount penalty | Works (in-container) |
| **Docker Compose watch** | 30s | Synced (200-500ms lag) | File sync latency | Requires `docker exec` |
| **Hybrid (chosen)** | 2-3 min first time | Native speed | No overhead | Full native access |
| **Devbox (Nix)** | 5+ min (Nix install) | Native speed | No overhead | Full native access |

### Decision: Hybrid Approach

App runs on disk with native hot-reload; infrastructure runs in Docker containers. This gives:

- **Native-speed hot-reload**: Vite HMR <100ms, Litestar --reload via watchfiles, no container boundary
- **Lowest resource usage on WSL2**: Only infra containers (~200-400MB RAM), no bind-mount penalty
- **Full Claude Code compatibility**: Direct filesystem access, all `make`/`uv`/`bun` commands work natively
- **Easy to extend**: Add test containers to a separate compose file without touching the app workflow

### Implementation

#### `make dev-setup` (One-Time)

Single command that chains all first-time steps:

```bash
make dev-setup
```

This:
1. Installs `uv` if missing
2. Installs `bun` if missing
3. Copies `.env.local.example` to `.env` if missing
4. Runs `make install` (Python venv + deps, JS deps)
5. Starts infrastructure containers
6. Waits for Postgres to be healthy
7. Applies database migrations

After setup, `make dev` starts the app server.

#### Procfile.dev (Concurrent Processes)

For running app server + SAQ worker together, a `Procfile.dev` is provided:

```
app: uv run app run
worker: uv run litestar workers run
```

Use with [overmind](https://github.com/DarthSim/overmind), [honcho](https://github.com/nickstenning/honcho), or [foreman](https://github.com/ddollar/foreman):

```bash
# With overmind (recommended — multiplexed output, tmux-based)
overmind start -f Procfile.dev

# With honcho (pure Python, available via uv)
uv run honcho start -f Procfile.dev
```

### Future: Devbox

If the team grows beyond 3-4 people and tool version drift becomes a problem, [Devbox](https://www.jetify.com/devbox) is the next step. It pins exact tool versions via Nix without requiring Nix expertise:

```json
{
  "packages": ["python@3.13", "uv@latest", "bun@latest"],
  "shell": { "init_hook": ["uv sync --all-extras --dev"] }
}
```

This is premature now — `uv` and `bun` already handle their own version management well.

---

## 3. Self-Contained Testing Infrastructure

### Problem

Integration tests relied on the same infrastructure containers used for development (shared Postgres, Redis). No mock external services existed — tests against FreePBX, Unifi, and Telnyx required real credentials or were skipped entirely.

### Solution: Isolated Test Stack + WireMock

#### docker-compose.test.yml

A completely isolated set of containers for testing, with no port conflicts with dev infrastructure:

| Service | Image | Dev Port | Test Port | RAM |
|---------|-------|----------|-----------|-----|
| PostgreSQL | `postgres:17-alpine` | 15432 | 25432 | ~30 MB |
| Valkey (Redis) | `valkey/valkey:latest` | 16379 | 26379 | ~10 MB |
| Mailpit | `axllent/mailpit:latest` | 18025/11025 | 28025/21025 | ~10 MB |
| RustFS (S3) | `rustfs/rustfs:latest` | 19000 | 29000 | ~30 MB |
| **WireMock** | `wiremock/wiremock:3.13.0-1` | — | 28080 | ~150 MB |
| **Total** | | | | **~230 MB** |

Key test optimizations:
- **Postgres**: `fsync=off`, `synchronous_commit=off`, `full_page_writes=off` + tmpfs for maximum speed
- **Valkey**: `appendonly no`, `save ""` — no persistence, pure in-memory
- **RustFS**: tmpfs storage — no disk writes

#### WireMock: One Container for All External APIs

All three external providers (FreePBX, Unifi, Telnyx) communicate via HTTP/JSON. A single WireMock container serves all three with path-based routing:

```
src/py/tests/fixtures/wiremock/
  __files/                          # Response body JSON files
    freepbx/
      token_response.json           # OAuth token response
      all_extensions.json           # GraphQL fetchAllExtensions response
    unifi/
      sites.json                    # GET /proxy/network/integration/v1/sites
      clients_site1.json            # GET .../sites/{id}/clients
    telnyx/
      phone_numbers.json            # GET /v2/phone_numbers
      phone_number_messaging.json   # GET /v2/phone_numbers/{id}/messaging
  mappings/                         # WireMock stub definitions
    freepbx-token.json              # POST /admin/api/api/token
    freepbx-graphql.json            # POST /admin/api/api/gql (with body matching)
    unifi-sites.json                # GET /proxy/network/integration/v1/sites
    unifi-clients.json              # GET .../sites/*/clients
    telnyx-phone-numbers.json       # GET /v2/phone_numbers
    telnyx-phone-number-messaging.json  # GET /v2/phone_numbers/*/messaging
```

#### Why Mocks, Not Real Services

| Service | Real Container | Mock (WireMock) | Decision |
|---------|---------------|-----------------|----------|
| FreePBX | 2 GB image, 60-90s start, needs MySQL | 150 MB shared, 3-5s start | **Mock** — code only hits HTTP/GraphQL |
| Unifi | 700+ MB, needs MongoDB, can't seed data | Shared with above | **Mock** — code only hits REST API |
| Telnyx | Cloud API, needs real credentials | Shared with above | **Mock** — REST API, deterministic stubs |

The value of integration tests is verifying our provider code correctly parses responses and handles errors — not verifying that FreePBX's GraphQL engine works.

#### Per-Test Scenarios

WireMock supports dynamic stub management via its Admin API. For tests that need specific scenarios (auth failure, timeout, empty results):

```python
import httpx

async def test_freepbx_auth_failure(wiremock_url: str):
    # Add a temporary stub for auth failure
    async with httpx.AsyncClient() as client:
        await client.post(f"{wiremock_url}/__admin/mappings", json={
            "request": {"method": "POST", "urlPath": "/admin/api/api/token"},
            "response": {"status": 401, "jsonBody": {"error": "invalid_client"}},
            "priority": 1  # Higher priority overrides default stub
        })
        # ... test code ...
        # Reset to default stubs
        await client.post(f"{wiremock_url}/__admin/mappings/reset")
```

#### Makefile Targets

```bash
make start-test-infra    # Start all test containers (isolated ports)
make stop-test-infra     # Stop test containers
make wipe-test-infra     # Remove test containers and volumes
make test-infra-logs     # Tail test container logs
make test-integration    # Start test infra, run integration tests, stop infra
```

#### pytest Fixture

Add to `src/py/tests/conftest.py`:

```python
@pytest.fixture(scope="session")
def wiremock_url() -> str:
    """WireMock server URL (started via make start-test-infra)."""
    return os.environ.get("WIREMOCK_URL", "http://localhost:28080")
```

### Decision: pytest-databases vs Testcontainers

The project already uses `pytest-databases` (from the Litestar ecosystem) for managing Postgres in tests. Adding `testcontainers` would create a parallel container management system. We chose to use the pre-started compose approach (`make start-test-infra` before `make test-integration`) because:

- Simpler — no container management code in tests
- Faster — containers stay running across test runs during development
- CI-friendly — `docker compose up -d` in a GitHub Actions step, then run tests
- Consistent — same compose file used locally and in CI

---

## 4. CI Integration

### Changes Made

The CI pipeline (`.github/workflows/ci.yaml`) now includes:

**Test job** — Starts the isolated test infrastructure (`docker-compose.test.yml`), sources `.env.test`, runs pytest with full service access, and tears down containers with `if: always()`.

**Frontend job** (new) — Runs `make tsc` (TypeScript type check) and `make test-frontend` (vitest) in parallel with the backend test job.

**Dependabot** — `dependabot.yaml` now covers GitHub Actions, pip (Python), and npm (JS) with weekly checks. Minor/patch updates are grouped. A new `dependabot-auto-merge.yaml` workflow auto-merges patch and minor Dependabot PRs when CI passes.

---

## 5. Error Tracking (GlitchTip / Sentry)

### Backend

`sentry-sdk[litestar]` added as a production dependency. `SentrySettings` class in `src/py/app/lib/settings.py` with `ENABLED`, `DSN`, `ENVIRONMENT`, `TRACES_SAMPLE_RATE`, `PROFILES_SAMPLE_RATE` fields. Initialization happens in `create_app()` before the Litestar app is constructed, so startup errors are captured. Integrations: `LitestarIntegration`, `SqlalchemyIntegration`. `send_default_pii=False`.

### Frontend

`@sentry/react` added. `src/js/web/src/lib/sentry.ts` exports `initSentry()`, called in `main.tsx` before React renders. Both error boundary components (`RootErrorBoundary` and the TanStack Router `ErrorBoundary`) call `Sentry.captureException()`.

### Self-Hosted GlitchTip

`tools/deploy/docker/docker-compose.glitchtip.yml` — 4-container stack (web, worker, Postgres, Valkey) at ~512MB RAM. Available at http://localhost:18090.

```bash
make start-glitchtip    # Start GlitchTip (http://localhost:18090)
make stop-glitchtip     # Stop
make wipe-glitchtip     # Remove with volumes
```

After starting, create an organization and project in the GlitchTip UI. Copy the DSN into your `.env`:

```
SENTRY_ENABLED=true
SENTRY_DSN=http://key@localhost:18090/1
VITE_SENTRY_DSN=http://key@localhost:18090/1
```

### Migration to Sentry

GlitchTip uses the standard Sentry SDK — migrating to Sentry (self-hosted or cloud) requires only changing the DSN URL.

---

## 6. Seed Data

`src/py/app/cli/seed.py` — Comprehensive development data seeder, runnable via:

```bash
make seed          # Populate DB with sample data (idempotent)
make seed-reset    # Wipe and re-seed
```

Seeded entities: 1 organization, 1 team, 5 users (with known login `admin@example.com` / `Test1234!@#$`), 2 locations, 5 phone numbers, 8 extensions, 6 voicemail boxes, 8 devices with line assignments, 3 fax numbers with email routes, 5 support tickets with message threads, 6 tags, 2 connections (FreePBX + Unifi), 3 E911 registrations, 4 notifications.

---

## 7. Staging Deployment

### Pipeline

1. PR merges to `main`
2. `deploy-staging.yaml` builds the distroless Docker image via Buildx with GHA cache
3. Image pushed to GHCR with tags `staging-<sha>` (rollback) and `staging-latest` (auto-pull)
4. Portainer webhook triggers stack redeployment

### Portainer Stack

`tools/deploy/docker/docker-compose.staging.yml` — Production-like stack that pulls pre-built images from GHCR. Services: db, cache, mailpit, migrator (run-once), app, worker. The migrator uses `service_completed_successfully` dependency so migrations always run before the app starts.

### Required Setup

- GitHub Actions secret: `PORTAINER_STAGING_WEBHOOK_URL`
- Portainer stack env vars: see `tools/deploy/docker/.env.staging.example`
- GHCR auth uses `GITHUB_TOKEN` automatically (no extra secrets)

---

## 8. Additional Workflow Improvements

### Pre-Push Check

```bash
make check      # ruff + biome + tsc + unit tests (~15 seconds)
make check-all  # Full lint + all tests + coverage
```

### PR Template

`.github/pull_request_template.md` with checklist: `make types`, `make tsc`, tests, migration needed.

### Branch Naming Convention

```
feat/voice-call-queues        # New feature
fix/device-null-mac           # Bug fix
chore/update-dependencies     # Maintenance
```

Documented in DEVELOPMENT.md. No CI enforcement (for now).

---

## 9. File Inventory

### New Files Created

| File | Purpose | Tracked |
|------|---------|---------|
| `AGENTS.md` | Universal AI directive file | Yes |
| `CLAUDE.md` | Symlink to AGENTS.md | No (gitignored) |
| `.claude/settings.json` | Project-level Claude Code permissions | Yes |
| `.claude/skills/new-domain/SKILL.md` | Scaffold new domain workflow | Yes |
| `.claude/skills/fix-issue/SKILL.md` | GitHub issue fix workflow | Yes |
| `.claude/skills/api-change/SKILL.md` | Post-API-change checklist | Yes |
| `Procfile.dev` | Concurrent process definitions (app + worker) | Yes |
| `.env.test` | Test environment variables | Yes |
| `tools/deploy/docker/docker-compose.test.yml` | Isolated test infrastructure | Yes |
| `tools/deploy/docker/docker-compose.glitchtip.yml` | GlitchTip error tracking stack | Yes |
| `tools/deploy/docker/docker-compose.staging.yml` | Staging Portainer stack | Yes |
| `tools/deploy/docker/.env.staging.example` | Staging env var template | Yes |
| `src/py/tests/fixtures/wiremock/mappings/*.json` | WireMock stub definitions (6 files) | Yes |
| `src/py/tests/fixtures/wiremock/__files/**/*.json` | WireMock response bodies (6 files) | Yes |
| `src/py/app/cli/seed.py` | Database seed script | Yes |
| `src/js/web/src/lib/sentry.ts` | Frontend Sentry initialization | Yes |
| `.github/workflows/deploy-staging.yaml` | Staging deploy pipeline | Yes |
| `.github/workflows/dependabot-auto-merge.yaml` | Auto-merge Dependabot PRs | Yes |
| `.github/pull_request_template.md` | PR checklist template | Yes |
| `DEVELOPMENT.md` | Comprehensive development guide | Yes |
| `FEATURE-WORKFLOW.md` | This document | Yes |

### Modified Files

| File | Change |
|------|--------|
| `.gitignore` | Track `.claude/settings.json` and `.claude/skills/`, ignore rest of `.claude/` |
| `Makefile` | Added `dev-setup`, `dev-all`, `check`, `seed`, `seed-reset`, `start-test-infra`, `stop-test-infra`, `wipe-test-infra`, `test-infra-logs`, `test-integration`, `start-glitchtip`, `stop-glitchtip`, `wipe-glitchtip` targets |
| `.github/workflows/ci.yaml` | Test job now uses docker-compose.test.yml + .env.test; new frontend job |
| `.github/dependabot.yaml` | Added pip and npm ecosystems, grouping, weekly schedule |
| `README.md` | Updated Quick Start and Key Commands sections, link to DEVELOPMENT.md |
| `pyproject.toml` | Added `sentry-sdk[litestar]` dependency |
| `src/py/app/lib/settings.py` | Added `SentrySettings` class |
| `src/py/app/server/asgi.py` | Added Sentry initialization in `create_app()` |
| `src/py/app/server/core.py` | Registered `seed_database` CLI command |
| `src/py/app/utils/env.py` | Added `float` type support to `get_env` |
| `src/js/web/src/main.tsx` | Added `initSentry()` call |
| `src/js/web/src/components/ui/error-boundary.tsx` | Added `Sentry.captureException()` |
| `src/js/web/src/components/error-boundary.tsx` | Added `Sentry.captureException()` |
| `src/js/web/package.json` | Added `@sentry/react` dependency |
| `.env` / `.env.local.example` | Added Sentry env vars |

---

## 10. Quick Reference

### New Developer Onboarding

```bash
git clone <repo>
cd admin-portal
make dev-setup    # ~2-3 minutes, does everything
make seed         # Populate DB with sample data (login: admin@example.com / Test1234!@#$)
make dev          # Start the app
```

### Daily Development

```bash
make start-infra  # If containers aren't running
make dev          # App server only
make dev-all      # App server + SAQ worker (requires overmind)
make check        # Quick pre-push validation (~15s)
```

### Running Tests

```bash
make test              # Backend unit tests (uses dev infra)
make test-frontend     # Frontend tests (vitest)
make test-integration  # Full integration tests (starts isolated test infra)
make test-all          # All tests
```

### After API Changes

```bash
make types   # Regenerate OpenAPI schema + TS client
make tsc     # Verify TypeScript compiles
```

### Error Tracking

```bash
make start-glitchtip   # Self-hosted error tracking (http://localhost:18090)
# Then configure SENTRY_DSN in .env
```

### AI-Assisted Development

```bash
# Claude Code skills (in Claude Code CLI):
/new-domain contacts       # Scaffold a new domain
/fix-issue 42              # Fix GitHub issue #42
/api-change added-field    # Run post-API-change checklist
```
