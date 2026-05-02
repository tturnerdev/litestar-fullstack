# Admin Portal

Litestar + React admin portal for managing telecom/UCaaS infrastructure.

## Build & Run

```bash
make dev-setup       # One-time: install tools, deps, infra, migrate DB
make dev             # Start app server (logs to error.log)
make start-infra     # Start Docker infra (Postgres, Valkey, Mailpit, RustFS)
make test            # Backend tests (pytest)
make test-frontend   # Frontend tests (vitest)
make test-all        # Both
make lint            # ruff + mypy + pyright + slotscheck + biome + codespell
make fix             # Auto-format (ruff + biome)
make types           # Regenerate OpenAPI schema + TS client (RUN AFTER ANY BACKEND API CHANGE)
make tsc             # TypeScript type check
make db-upgrade      # Apply pending database migrations
make db-migrate m="description"  # Create a new Alembic migration
```

- Python: `uv` (package manager), Python 3.13
- JavaScript: `bun` (runtime + package manager)
- Infra: Docker Compose for Postgres (15432), Valkey/Redis (16379), Mailpit (18025), RustFS/S3 (19000)

## Architecture

- **Backend**: `src/py/app/` — Litestar framework, domain-driven with auto-discovery plugin
- **Frontend**: `src/js/web/src/` — React 19, TanStack Router (file-based), React Query, Zustand, shadcn/ui
- **DB models**: `src/py/app/db/models/` — SQLAlchemy 2.0, UUIDv7 primary keys, one class per file
- **Schemas**: msgspec `CamelizedBaseStruct` (auto camelCase conversion); Update types use `msgspec.UNSET`
- **Services**: inherit `SQLAlchemyAsyncRepositoryService[Model]` from Advanced Alchemy
- **Controllers**: use `create_service_dependencies()` for DI with type-safe filters
- **Task queue**: SAQ (Simple Async Queue) on Redis, jobs defined in domain `jobs.py` files
- **API client**: auto-generated from OpenAPI spec at `src/js/web/src/lib/generated/`

## Domain Pattern

Each domain lives at `src/py/app/domain/<name>/` with this structure:

```
src/py/app/domain/<name>/
  __init__.py          # Exports controller list for auto-discovery
  controllers/         # Route handlers (one per resource)
  services/            # Business logic (repository service pattern)
  schemas/             # Request/response types (List/Detail/Create/Update)
  deps.py              # Dependency injection (create_service_dependencies)
  guards.py            # Authorization guards (plain functions)
  listeners.py         # Event handlers (@listener decorator)
  jobs.py              # Background tasks (SAQ)
```

Corresponding frontend structure:
- Routes: `src/js/web/src/routes/_app/<name>/`
- API hooks: `src/js/web/src/lib/api/hooks/<name>.ts`

Existing domains: accounts, admin, connections, devices, e911, events, fax, gateway, locations, notifications, organizations, schedules, support, system, tags, tasks, teams, voice

## Code Style

- One class per file (e.g., `_user.py`), exported from `__init__.py`
- Separate schema types: `<Entity>`, `<Entity>List`, `<Entity>Create`, `<Entity>Update`
- Guards: plain functions `(connection, handler) -> None`, raise `PermissionDeniedException`
- Events: `@listener("event_name")` for async side effects
- Frontend layouts: `createFileRoute()`, `PageContainer`/`PageHeader`/`PageSection`
- Git: conventional commits (`feat:`, `fix:`, `chore:`, etc.)
- Pre-commit: ruff (Python lint/format), biome (JS/TS lint), codespell

## Important Rules

- After ANY backend schema or endpoint change, run `make types` to regenerate the API client
- Never modify `src/js/web/src/lib/generated/` by hand — it's auto-generated
- Prefer running targeted tests over the full suite during development
- External service integrations go through the `gateway` domain's provider pattern
- All gateway providers (FreePBX, Unifi, Telnyx) communicate via HTTP/JSON only
- DB migrations: create with `make db-migrate m="description"`, apply with `make db-upgrade`

## Testing

- Backend: pytest with unit (`src/py/tests/unit/`) and integration (`src/py/tests/integration/`) directories
- Frontend: vitest (`cd src/js/web && bun run test`)
- Test infra: `make start-test-infra` spins up isolated containers including WireMock for external API mocks
- Markers: `@pytest.mark.integration`, `@pytest.mark.unit`, `@pytest.mark.slow`, `@pytest.mark.external`
- Factories: Polyfactory-based in `src/py/tests/factories.py`
- Coverage: 65% minimum enforced

## External Integrations

All managed via the Connections domain and Gateway providers:
- **FreePBX**: GraphQL API (OAuth2 token + `/admin/api/api/gql`)
- **Unifi**: REST API (`/proxy/network/integration/v1/`)
- **Telnyx**: REST API (`/v2/phone_numbers`, `/v2/faxes`)

Test stubs: WireMock mappings at `src/py/tests/fixtures/wiremock/`
