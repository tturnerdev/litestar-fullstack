# Changelog

## v0.27.0 (2026-04-30)

### Improved
- **Voice voicemail page** — breadcrumbs with extension name, dynamic header badges (disabled/unread/total), skeleton loading state, and proper empty state for messages list.
- **Admin user detail page** — hero section with gradient avatar, security indicators, organized sections (Account Info, Activity, Admin Actions, Teams, OAuth, Danger Zone), inline toggles for active/superuser/verified, copy buttons, relative timestamps, and role badges.

## v0.26.0 (2026-04-30)

### Improved
- **Fax number detail page** — organized sections (Number Info, Email Routes, Recent Messages, Metadata), formatted phone number display, inline active toggle, message count summary, send fax quick link, copy buttons, and relative timestamps.
- **Fax message detail page** — organized sections (Message Info, Transmission Details, Content preview, Metadata), direction/status badges, PDF preview iframe, error banners for failed messages, copy buttons, and danger zone delete.

## v0.25.0 (2026-04-30)

### Improved
- **Admin domain pages** (devices, fax, voice, support) — colored icon stat cards with hover links, loading skeletons, error states, empty states, recent items tables, section headers with descriptions, and "View all" navigation buttons.
- **Voice extension detail page** — organized into sectioned cards (Info, Call Settings, Metadata) with inline active toggle, DND/forwarding/voicemail summaries, copy buttons, relative timestamps, and delete confirmation.
- Extension schema now includes `created_at` and `updated_at` fields.

## v0.24.0 (2026-04-30)

### Improved
- **Admin dashboard** — stat cards with trend indicators (up/down arrows), improved activity feed with action icons and actor names, system health with per-service icons and worker queue stats, additional quick action links.
- **Settings page** — sticky sidebar navigation, theme preview cards with UI wireframes, toast confirmations on every change, "Reset to defaults" button, keyboard shortcuts section, bordered display preference rows, and colored notification category icons with active count.

## v0.23.0 (2026-04-30)

### Improved
- **Admin teams page** — search, sortable columns, bulk delete, member counts, active/inactive status indicators, relative timestamps, export, and pagination. `useAdminTeams` hook now supports named params with sort.
- **Admin audit log** — unified search, multi-select action/resource type filters, date range presets (today/7d/30d/90d/custom), sortable columns, removable filter chips, expandable detail rows with 3-column layout, and CSV export options.

## v0.22.0 (2026-04-30)

### Improved
- **Admin users page** — search, role/status filters, sortable columns, bulk activate/deactivate/delete, inline toggle buttons for role and active status, user avatars, relative timestamps, and export. `useAdminUsers` hook now supports named params with sort.
- **Profile page** — gradient banner with larger avatar, role badges, security status indicators with tooltips, connected accounts + sessions in two-column grid, quick links card to settings sections.

## v0.21.0 (2026-04-30)

### Improved
- **Teams list page** — table layout with search, sortable columns, bulk delete, member counts, role badges, and result counts. New `useTeams` and `useDeleteTeam` hooks.
- **Team detail page** — breadcrumbs, team ID copy button, member count on tab, status/role badges in header, skeleton loading state.
- **Voice phone numbers page** — search, type/status filters, sortable columns, bulk delete, edit dialog for label/caller ID, and improved empty states.

## v0.20.0 (2026-04-30)

### Improved
- **Support ticket detail page** — two-column layout with conversation thread and metadata sidebar. Quick-change dropdowns for status/priority, organized timeline with copy buttons, inline reopen button on closed tickets.
- **Fax numbers list page** — search, active/inactive filter, sortable columns, bulk delete, status indicators, email routes column, quick link to messages, and card/table view toggle.

## v0.19.0 (2026-04-30)

### Improved
- **Device detail page** — reorganized into sectioned cards (Info, Network, Lines/Extensions, Metadata) with copy buttons for MAC/IP/ID, reboot/reprovision confirmation dialogs in header, relative timestamps, and assigned lines display.
- **Voice extensions list page** — search by number/name, active/inactive filter, sortable columns, bulk delete/export, phone number resolution from IDs, relative timestamps, and row-click navigation to detail.

## v0.18.0 (2026-04-30)

### Improved
- **Connection detail page** — reorganized into sections (Info, Server, Auth, Settings, Metadata) with icons, test-connection button with inline results, copy buttons for host/ID, relative timestamps with tooltips, and delete confirmation dialog.
- **Fax messages list page** — search, direction/status filters, sortable columns, bulk delete, relative timestamps, error message tooltips, page count badges, and fax line name lookup.

## v0.17.0 (2026-04-30)

### Improved
- **Devices list page** — table view with search, type/status filter dropdowns, sortable columns, bulk delete, per-row reboot/reprovision buttons, IP address column, and last-seen timestamps. Device status badges now use colored dot indicators with pulse animation for provisioning state.
- **Support tickets list page** — search, status/priority/category filters, sortable columns, bulk close/delete, relative timestamps, category badges, and improved empty states.

## v0.16.0 (2026-04-30)

### Improved
- **Connections list page** — table view with search, type/status filter dropdowns, sortable columns, checkbox bulk-delete, per-row quick test button, last-tested timestamps, and clear empty states.
- **Home dashboard** — feature areas grid with quick-access cards for Connections, Devices, Voice, Fax, Support, and Tags. Each card shows entity count and links to the area's list page.

### Added
- `useTestAnyConnection()` hook for testing connections by ID from list views.
- `FeatureAreasGrid` component with responsive layout and live counts.

## v0.15.0 (2026-04-29)

### Added
- **Fax email routes page** (`/fax/email-routes`) — full management UI with table, create/edit/delete dialogs, fax number association, failure alert toggles. "Email Routes" card added to fax dashboard.
- **Tags in sidebar navigation** — "Tags" section added to app sidebar with "All tags" and "Create new" sub-items.

## v0.14.0 (2026-04-29)

### Added
- **Voice extension create page** (`/voice/extensions/new`) — form with extension number, display name, phone number assignment, and active toggle.
- **Voice extension edit page** (`/voice/extensions/:id/edit`) — pre-populated form with dirty-field diffing, extension number shown read-only. Edit button added to detail page.
- **Fax number create page** (`/fax/numbers/new`) — form with number, label, and active toggle. "New Number" button added to list page.
- **Fax number edit page** (`/fax/numbers/:id/edit`) — pre-populated form for label and active status. Edit button added to detail page.

## v0.13.0 (2026-04-29)

### Added
- **Tags frontend** — complete CRUD UI for tags: list page with search and delete confirmation, create page, edit page. New React Query hooks (`useTags`, `useTag`, `useCreateTag`, `useUpdateTag`, `useDeleteTag`).
- **Support ticket edit page** (`/support/:id/edit`) — edit subject, status, priority, and category with dirty-field diffing. Edit button added to ticket detail page.

## v0.12.0 (2026-04-29)

### Added
- **Connection edit page** (`/connections/:id/edit`) — full form to update connection name, type, provider, host, port, auth type, credentials, description, SSL verification, and settings. Credentials are masked; only re-entered values are sent in the update.
- **Device edit page** (`/devices/:id/edit`) — full form to update device name, type, MAC address, model, manufacturer, firmware version, and IP address. Only changed fields are submitted.
- **Edit buttons** on Connection and Device detail pages linking to their respective edit forms.

## v0.11.0 (2026-04-29)

### Added
- **Gateway API** (`/api/gateway/numbers`, `/api/gateway/extensions`, `/api/gateway/devices`) — multi-source lookup that fans out queries to all configured connections.
- **FreePBX GraphQL provider** — OAuth2 client-credentials auth with token caching, extension/number/device queries, Follow Me, ring group membership, call forwarding, recording settings, DND status.
- **Telnyx REST provider** — API key auth, phone number lookup with messaging profile and E911/CNAM data.
- **Provider registry** with `@register_provider` decorator for auto-discovery.
- **Connection creation form** improvements — team ID auto-population, SSL toggle, OAuth2 scopes input.
- **`useAuth` hook** now exposes `currentTeam` and `teams`.
