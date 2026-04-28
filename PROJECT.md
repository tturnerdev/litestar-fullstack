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

| # | Area | Domain Module | Description | Status |
|---|------|---------------|-------------|--------|
| 1 | **Device** | `app.domain.devices` | Device provisioning, configuration, and status monitoring | Implemented |
| 2 | **Voice** | `app.domain.voice` | Phone, extension, voicemail, forwarding, and DND settings | Implemented |
| 3 | **Fax** | `app.domain.fax` | Fax number management and email delivery configuration | Implemented |
| 4 | **Support** | `app.domain.support` | Helpdesk ticket system with markdown and image support | Implemented |
| 5 | **Location** | `app.domain.locations` | Addressed and physical sub-locations for associating devices and extensions | Implemented |
| 6 | **Organization** | `app.domain.organizations` | Org-level settings and profile (admin-viewable, superuser-editable) | Implemented |
| 7 | **Connections** | `app.domain.connections` | External integration configs (PBX, helpdesk, carrier) with credential security | Implemented |

Detailed plans for the original four domains: [FEATURE-DEVICE.md](./FEATURE-DEVICE.md), [FEATURE-VOICE.md](./FEATURE-VOICE.md), [FEATURE-FAX.md](./FEATURE-FAX.md), [FEATURE-SUPPORT.md](./FEATURE-SUPPORT.md)

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

- Top-level sidebar entries: **Teams**, **Locations**, **Devices**, **Voice**, **Fax**, **Support**.
- Superuser-only entries: **Connections**, **Organization**, **Admin**.
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

## Implementation Status

All seven domain modules are implemented with full backend (models, services, controllers, schemas, guards, migrations) and frontend (routes, components, API hooks).

### Access Control

| Role | Visible Domains |
|------|----------------|
| Member | Teams, Locations, Devices, Voice, Fax, Support |
| Admin | All member domains + view Organization |
| Superuser | All domains + edit Organization, Connections, Admin |

### Upcoming Work

- **API Sync System** — Pull data from external sources (carrier phone numbers, PBX extensions, helpdesk tickets) into portal tables via the Connections domain. Provider-specific adapters behind a common interface, executed as SAQ background jobs.
- **File/Image Upload Service** — Needed by Support (ticket attachments) and potentially Device (firmware uploads).
- **Notification Service** — Email and in-app notifications for ticket updates, device alerts, voicemail delivery.
- **Audit Logging** — Extend the admin audit log viewer to cover all domain entity types.
- **Cross-Domain Linking** — Associate devices and extensions with physical locations; link connections to their respective data domains.
