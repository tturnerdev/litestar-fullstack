# Release v0.1.0

## Summary

First feature-complete release of the Admin Portal. Introduces 8 new domain modules (Devices, Voice, Fax, Support, Locations, Connections, Organization, Notifications), a comprehensive audit logging system, and extensive UI enhancements across the frontend.

---

## New Domains

### Devices
- Full CRUD for device management with type, status, and line configuration
- Frontend with search/filter, tabbed detail view, bulk actions, and CSV export

### Voice
- Extensions, phone numbers, DND, voicemail, and call forwarding
- Create dialogs for extensions and phone numbers
- Extension detail page with settings tabs (DND, voicemail, forwarding)
- Auto-provisioning of DND and voicemail records on first access

### Fax
- Fax numbers, email routes, and message management
- Send fax page, message detail with status tracking
- Email-to-fax routing configuration

### Support / Helpdesk
- Ticket lifecycle with threaded messages and attachments
- Markdown editor and renderer for ticket messages
- Feedback email endpoint and issue reporting form
- Rich ticket detail with header, message thread, and action bar

### Locations
- Location management with addressed and physical types
- Team-scoped location assignment

### Connections
- External integration configuration (admin/superuser only)
- Connection types with auth credentials and status

### Organization
- Platform-level settings (admin/superuser only)
- Organization stats dashboard and admin quick links

### Notifications
- In-app notification system with bell icon and unread count
- Notification triggers wired to domain events (tickets, teams, devices, voice, fax)
- Mark read/unread, mark all read, delete

## Audit Logging
- Comprehensive audit trail with before/after change tracking
- Field-level diffs stored in JSONB details column
- Wired to all domain controllers (~71 call sites)
- Admin UI with date range filters, action type filters, actor/target search
- Expandable detail rows with diff viewer
- CSV export with Basic and Extended modes

## UI Enhancements
- **Global Search**: Cmd+K command palette searching across all entity types
- **Keyboard Shortcuts**: `g+h/t/d/s/p/a` navigation sequences, `?` help dialog, `n` context-sensitive create
- **Breadcrumb Navigation**: Consistent breadcrumbs on all detail and creation pages
- **Empty States**: Contextual empty states across all list pages
- **Error Boundary**: Global error boundary with recovery and 404 page
- **Settings Page**: Theme (light/dark/system), notification preferences, display density
- **Bulk Actions**: Row selection with bulk delete and CSV export on tables
- **Sidebar Badges**: Team and user count badges on navigation items
- **Home Dashboard**: Stats cards, teams list, quick actions, recent activity (admin)
- **Profile Page**: Profile editing, password change, and account management
- **Help Menu**: Resource links and issue reporting
- **Dark Mode Fixes**: Proper hover contrast on Quick Actions icons

## Bug Fixes
- Fixed React Query cache poisoning from shared query keys with different return shapes
- Fixed TanStack Router code-split warnings from unused layout exports
- Fixed notification migration NameError (`Sequence` under TYPE_CHECKING)
- Fixed voice DND/voicemail 500 errors with race-condition-safe get-or-create
- Fixed notification metadata serialization (SQLAlchemy MetaData vs dict)
- Fixed search controller crash from TYPE_CHECKING User import
- Fixed sidebar crash from non-array API response shape
- Fixed duplicate migration revision IDs
- Fixed team invitation accept flow for non-members
- Fixed device model naming collision with Advanced Alchemy

## Infrastructure
- `make dev` / `make dev-debug` targets with error.log streaming via tee
- Role-based permissions with feature area scoping for teams
- Generic entity sync endpoint with field-based lookup

- Admin Users management: manage roles (system + team), join team, view permissions dialogs
- Audit log enrichment: `actor_name` column with display name, improved target labels on MFA events
