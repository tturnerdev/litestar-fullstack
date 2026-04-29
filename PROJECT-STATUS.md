# Project Status — Admin Portal

**Date:** 2026-04-28
**Branch:** `dev` (pushed, 40 commits ahead of `main`)

---

## Completed Domains

All seven domain modules are implemented end-to-end (backend + frontend):

| Domain | Backend | Frontend | Audit Logging | Delete Support |
|--------|---------|----------|---------------|----------------|
| **Accounts** | Controllers for auth, MFA, OAuth, profile, roles | Profile page, MFA, connected accounts | Yes | N/A (admin only) |
| **Teams** | Team, invitations, members, role permissions | List, detail, create, invite, permissions | Yes | Yes |
| **Devices** | CRUD, ownership guards | List, detail, create, search/filter, tabbed view | Yes | Yes |
| **Voice** | Extensions, phone numbers, forwarding, voicemail, DND | List, detail, create, settings forms | Yes | Yes |
| **Fax** | Numbers, email routes, messages | List, detail, send, email route editor | Yes | Yes |
| **Support** | Tickets, messages, attachments, feedback | List, detail, create, markdown editor, file upload | Yes | Yes |
| **Locations** | CRUD, team-scoped | List, detail, create form | Yes | Yes |
| **Connections** | CRUD, credential masking, admin-only | List, detail, create | Yes | Yes |
| **Organizations** | Get/update org settings, superuser-only | Settings page | Yes | N/A (singleton) |
| **Admin** | Audit log viewer, user/team management | Dashboard, stats, users table, teams table, audit log | Yes | Yes |

## Cross-Cutting Features Completed

| Feature | Status | Details |
|---------|--------|---------|
| **Audit Logging** | Done | `capture_snapshot`/`log_audit` in all 16+ controllers (~50 audit calls). Before/after diff, JSONB details, enhanced admin viewer with expandable diffs. |
| **Delete Functionality** | Done | All entities that can be created can be deleted. Confirmation dialogs on frontend. |
| **Help Menu / Report Issue** | Done | `?` icon in header, tabbed dialog (Resources + Report Issue), screenshot capture via html2canvas, file upload, sends HTML email to support@atrelix.com. |
| **Entity Sync Endpoint** | Done | `GET /api/sync/{domain}/{field}/{value}` with 8 domain mappings. |
| **Team Permissions** | Done | Role-based permissions with feature area scoping. |
| **Navigation** | Done | Full sidebar with all domains, role-based visibility (superuser sees Connections/Organization/Admin). |
| **Generated Types** | Done | OpenAPI spec + TypeScript client regenerated and committed. |

## Architecture

- **Backend:** Litestar + SQLAlchemy 2.0 + Advanced Alchemy, domain-driven layout at `src/py/app/domain/`
- **Frontend:** React 19 + TanStack Router (file-based) + React Query + shadcn/ui
- **DB:** PostgreSQL, UUIDv7 PKs, Alembic migrations
- **Schemas:** msgspec `CamelizedBaseStruct` (auto camelCase)
- **API Client:** Auto-generated via `@hey-api/openapi-ts` (`make types`)

## Outstanding / Next Steps

### High Priority
1. **Home Dashboard Enhancement** — Currently shows only teams list and quick actions. Should show activity feed, recent tickets, device status, voicemail count, and other domain summaries.
2. **Admin User Management** — Admin user table exists but may lack edit/create/deactivate actions beyond what's already there.
3. **Profile Page Enhancement** — Only shows MFA and connected accounts. Missing: name/email edit, avatar upload, password change, notification preferences.
4. **Frontend Sync Buttons** — The backend sync endpoint exists but frontend sync buttons (to trigger lookups from external sources) are not wired up yet.

### Medium Priority
5. **Notification System** — No in-app notification system. Needed for ticket updates, team invitations, device alerts, voicemail delivery.
6. **Search / Global Search** — No global search across entities (devices, tickets, teams, etc.).
7. **Admin Audit Log Enhancements** — Could add export to CSV, date range filtering, real-time streaming.
8. **Fax Send Integration** — Send fax form exists but actual fax transmission via carrier API (Connections domain) is not wired.
9. **Voicemail Playback** — Voicemail player component exists but actual audio file storage/retrieval may not be complete.

### Lower Priority
10. **Testing** — No unit/integration tests written yet for any domain.
11. **Dark Mode Polish** — Theme toggle exists but some components may not be fully themed.
12. **Mobile Responsiveness** — Sidebar collapses but list/detail views may not be fully responsive.
13. **Bulk Operations** — No bulk delete/update for any domain lists.
14. **Data Export** — No CSV/Excel export for any domain tables.

## File Counts

| Area | Files |
|------|-------|
| Backend controllers | ~25 files across 10 domains |
| Backend models | ~20 model files |
| Frontend routes | ~30 route files |
| Frontend components | ~50 component files |
| API hooks | 10 hook files |
| DB migrations | ~15 migration files |
