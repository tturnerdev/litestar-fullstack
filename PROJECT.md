# Platform Dashboard — Feature Implementation Plan

## Overview

This document outlines the implementation plan for four new feature areas in the platform dashboard. Each area introduces a new **domain module** following the existing architecture established by the `accounts`, `teams`, and `admin` domains.

The platform is built on the [Litestar Fullstack](https://github.com/litestar-org/litestar-fullstack) reference architecture with:

| Layer | Technology |
|---|---|
| Backend API | Litestar (Python ASGI) |
| ORM / DB | SQLAlchemy 2.0 + PostgreSQL via Advanced Alchemy |
| Schemas / DTOs | msgspec Structs (`CamelizedBaseStruct`) |
| Migrations | Alembic |
| Task Queue | SAQ + Redis |
| Frontend | React 19 + Vite + TanStack Router + React Query |
| UI Components | shadcn/ui (Radix-based) + Tailwind CSS |
| API Client | Auto-generated via `@hey-api/openapi-ts` |
| State | Zustand |

---

## Feature Areas

| # | Area | Domain Module | Description | Detailed Plan |
|---|------|---------------|-------------|---------------|
| 1 | **Device** | `app.domain.devices` | Device provisioning, configuration, and status monitoring | [FEATURE-DEVICE.md](./FEATURE-DEVICE.md) |
| 2 | **Voice** | `app.domain.voice` | Phone, extension, voicemail, forwarding, and DND settings | [FEATURE-VOICE.md](./FEATURE-VOICE.md) |
| 3 | **Fax** | `app.domain.fax` | Fax number management and email delivery configuration | [FEATURE-FAX.md](./FEATURE-FAX.md) |
| 4 | **Support** | `app.domain.support` | Helpdesk ticket system with markdown and image support | [FEATURE-SUPPORT.md](./FEATURE-SUPPORT.md) |

---

## Architecture Conventions

Every new domain follows the established pattern:

```
src/py/app/domain/<domain_name>/
├── __init__.py
├── controllers/
│   ├── __init__.py
│   └── _<resource>.py          # One controller per resource
├── services/
│   ├── __init__.py
│   └── _<resource>.py          # Business logic per resource
├── schemas/
│   ├── __init__.py
│   └── _<resource>.py          # msgspec DTOs (List/Detail/Create/Update)
├── deps.py                      # Service providers (create_service_provider)
├── guards.py                    # Authorization guards
└── listeners.py                 # Event listeners (optional)
```

**Database models** live in `src/py/app/db/models/` with a `_<name>.py` file per model, all inheriting from `UUIDv7AuditBase`.

**Frontend** additions follow:

```
src/js/web/src/
├── routes/_app/<domain>/        # File-based routes (TanStack Router)
│   ├── index.tsx                # List view
│   ├── new.tsx                  # Create form (if applicable)
│   └── $<id>/
│       └── index.tsx            # Detail / settings view
├── components/<domain>/         # Domain-specific React components
└── lib/api/hooks/<domain>.ts    # React Query hooks
```

After backend changes, run `make types` to regenerate the TypeScript API client.

---

## Cross-Cutting Concerns

### Authentication & Authorization

- All new routes sit behind the `_app` layout (JWT-authenticated).
- Guards enforce resource-level access (e.g., "user owns this device", "user can manage this fax number").
- Admin overrides follow the existing `requires_superuser` / role-based pattern.

### Navigation

- New top-level sidebar entries: **Devices**, **Voice**, **Fax**, **Support**.
- The admin panel (`/admin`) will gain management views for each domain.

### Database Migrations

- Each feature area introduces new tables via Alembic migrations.
- Migrations must be additive; never drop existing columns in the initial rollout.
- All models use `UUIDv7` primary keys and include `created_at` / `updated_at` audit columns.

### API Design

- REST endpoints under `/api/<domain>/` (e.g., `/api/devices`, `/api/voice/extensions`).
- Pagination via Advanced Alchemy `OffsetPagination`.
- Filtering via `create_service_dependencies()` filter definitions.
- All response schemas use `CamelizedBaseStruct` for automatic camelCase keys.

### Testing Strategy

- Unit tests for services (business logic).
- Integration tests for controllers (HTTP round-trips).
- Frontend component tests where interaction logic is non-trivial.
- Minimum 65% coverage per module (matches project standard).

### Event-Driven Side Effects

- Use `@listener` for async operations like sending notifications, logging audit events, or syncing with external systems.
- Background tasks via SAQ for long-running operations (e.g., device provisioning, file uploads).

---

## Implementation Order

The recommended order balances dependency relationships and incremental value:

```
Phase 1: Device
  └── Foundation — models, CRUD, device status
  └── Establishes the pattern for hardware-linked entities

Phase 2: Voice
  └── Depends on Device (extensions tied to devices)
  └── Core telephony settings

Phase 3: Fax
  └── Lighter scope, self-contained
  └── Fax number + email delivery mapping

Phase 4: Support
  └── Most complex frontend (rich text editor, image handling)
  └── Can be developed in parallel with Phases 2–3
```

Each phase is detailed in its own `FEATURE-*.md` file linked above.

---

## Shared Infrastructure Needs

Before or during Phase 1, the following shared infrastructure should be established:

1. **File/Image Upload Service** — Needed by Support (ticket attachments) and potentially Device (firmware uploads). Should be a shared service in `app.lib` or its own domain.
2. **Notification Service** — Email and in-app notifications for ticket updates, device alerts, voicemail delivery. Extends the existing email infrastructure.
3. **Audit Logging** — All four domains should emit audit events. The existing admin audit log viewer should be extended to cover new entity types.
4. **Webhook/External Integration Layer** — Support helpdesk integration, device provisioning callbacks, voicemail transcription. A shared pattern for external API communication.
