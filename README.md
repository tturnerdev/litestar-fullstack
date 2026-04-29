<!-- markdownlint-disable -->
<p align="center">
  <img src="https://raw.githubusercontent.com/litestar-org/branding/1dc4635b192d29d864fcee6f3f73ea0ff6fecf10/assets/Branding%20-%20SVG%20-%20Transparent/Fullstack%20-%20Banner%20-%20Inline%20-%20Light.svg#gh-light-mode-only" alt="Litestar Logo - Light" width="100%" height="auto" />
  <img src="https://raw.githubusercontent.com/litestar-org/branding/1dc4635b192d29d864fcee6f3f73ea0ff6fecf10/assets/Branding%20-%20SVG%20-%20Transparent/Fullstack%20-%20Banner%20-%20Inline%20-%20Dark.svg#gh-dark-mode-only" alt="Litestar Logo - Dark" width="100%" height="auto" />
</p>
<!-- markdownlint-restore -->

# Admin Portal

A multi-tenant administration portal built on the [Litestar Fullstack](https://github.com/litestar-org/litestar-fullstack) reference architecture.

## Stack

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

## Feature Domains

| Domain | Module | Description |
|--------|--------|-------------|
| **Teams** | `app.domain.teams` | Team management, member roles, invitations with email notifications |
| **Devices** | `app.domain.devices` | Device provisioning, configuration, line assignments, and status monitoring |
| **Voice** | `app.domain.voice` | Phone numbers, extensions, voicemail, forwarding rules, and DND settings |
| **Fax** | `app.domain.fax` | Fax number management and email delivery routing |
| **Support** | `app.domain.support` | Helpdesk ticket system with markdown, attachments, and message threads |
| **Locations** | `app.domain.locations` | Addressed locations (with mailing address) and physical sub-locations for associating devices and extensions |
| **Organization** | `app.domain.organizations` | Org-level settings and profile (admin-viewable, superuser-editable) |
| **Connections** | `app.domain.connections` | External integration configs (PBX, helpdesk, carrier) with credential security and health checks |
| **Notifications** | `app.domain.notifications` | In-app notification system with bell icon, unread counts, and domain event triggers |
| **Admin** | `app.domain.admin` | User management, audit logging with field-level diffs, and platform dashboard |

## Platform Features

- **Global Search** — `Cmd+K` command palette searching across all entity types
- **Keyboard Shortcuts** — `g+h/t/d/s/p/a` navigation sequences, `?` help dialog, `n` context-sensitive create
- **Audit Logging** — Comprehensive audit trail with before/after change tracking, field-level diffs, actor enrichment, CSV export (Basic/Extended)
- **Notifications** — In-app notifications wired to domain events (tickets, teams, devices, voice, fax) with mark read/unread and bulk actions
- **Settings** — Theme (light/dark/system), notification preferences, display density
- **Role-Based Access** — Feature-area-scoped permissions per team, admin and superuser guards

See [PROJECT.md](./PROJECT.md) for architecture conventions and detailed feature plans.

## Quick Start

```shell
make install
. .venv/bin/activate
```

### Local Development

```bash
cp .env.local.example .env
. .venv/bin/activate
make start-infra
app database upgrade
app run
```

For development with error logging:

```bash
make dev          # stdout+stderr logged to error.log
make dev-debug    # same, with Litestar debug mode
```

### Docker

```bash
docker compose up
```

### After Backend Changes

Regenerate the TypeScript API client and route manifest:

```bash
make types
```
