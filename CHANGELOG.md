# Changelog

## v0.73.0 (2026-04-30)

### Fixed
- **Accessibility: ARIA labels** — Added `aria-label` to all icon-only buttons missing accessible names: fax table copy/refresh, organization copy, notification mark-read/delete, getting-started dismiss, password toggle in login/signup forms, email verification banner. Added `aria-label` to all admin data tables (support, fax, devices, voice, users, teams) for screen reader identification.
- **Loading states** — Replaced Loader2 spinners with proper Skeleton/SkeletonCard placeholders in team-list, notifications page, and gateway lookup results.
- **Error states** — Added missing `isError` handling with EmptyState component to home dashboard (5 queries), profile page, and team invitation acceptance page.

## v0.71.0 (2026-04-30)

### Improved
- **Truncation tooltips (final sweep)** — Completed app-wide tooltip coverage on all truncated text: voicemail transcription previews, recent-activity-card, fax message file paths, profile link descriptions, stat-card labels, send-fax filenames, team-list (grid+list views), profile-info-card, fax-number-card, nav-user (sidebar+dropdown), recent-activity (actor+target), teams-card.
- **Unsaved changes warnings** — Added `useBlocker()` navigation protection with AlertDialog to tag edit, extension edit, and fax number edit forms. All edit forms now warn before discarding unsaved changes.
- **Character counters** — Added visible character counters to tag edit name field (50 max) and device form name field (100 max) with amber/red color warnings near limits.

## v0.69.0 (2026-04-30)

### Improved
- **Truncation tooltips (comprehensive sweep)** — Added Tooltip wrappers on all truncated text across the app: device-card (MAC, model, IP, last seen), top-users-card (name, email), admin support tables (ticket subjects), ticket-list-item (subject), audit-log (user agent), ticket detail page (creator/assignee names and emails), ticket-detail-header (reporter/assignee), admin teams (team name), edit-user-dialog (email), join-team-dialog (name, email), attachment-list/upload (filenames), ticket-message (author), organization page (logo URL).
- **Table row hover** — Added `hover:bg-muted/50 transition-colors` to all remaining data TableRows: admin support, fax, devices, voice pages, device-line-config, fax email-routes.
- **Gateway page** — Replaced bare "No data" text with icon-accompanied descriptive messages.
- **System admin page** — Changed generic "No data available" to specific labels ("Not detected", "No workers running").

## v0.66.0 (2026-04-30)

### Fixed
- **Spinner consistency** — Replaced custom CSS spinner divs with Loader2 component in notification-bell, team-list, and ticket-conversation for consistent loading indicators.
- **Table row hover** — Added `hover:bg-muted/50 transition-colors` to data table rows in admin user-table, connections index, and teams index for consistent interaction feedback.

## v0.65.0 (2026-04-30)

### Improved
- **Location list table** — Tooltips on truncated descriptions (>80 chars) and long addresses (>50 chars), row hover and alternating stripes, Edit action with Pencil icon linking to edit page, MapPin icons before addresses, Building2/MapPin icons on type badges, Eye icon on View details.
- **Phone number format** — Standardized phone-number-card to `(XXX) XXX-XXXX` format matching the rest of the app.

## v0.64.0 (2026-04-30)

### Fixed
- **AlertDialog sweep** — Converted ALL remaining delete/destructive confirmation dialogs from `Dialog` to `AlertDialog` across the entire frontend. Affected: fax message list (single + bulk delete), extension detail delete, fax number delete, fax message detail delete, support ticket delete (header + detail), email route delete, connection delete, forwarding rule delete, device action destructive confirm, location delete, MFA disable. AlertDialog prevents accidental dismissal by clicking outside the overlay.

### Improved
- **MFA disable dialog** — Loader2 spinners on confirm, improved security warning text, cancel button, password autoComplete.
- **Notifications page** — AlertDialog for bulk delete-all-read, timestamp tooltips, category count badges on filters, hover ChevronRight for actionable items, Loader2 consistency, entrance animations.
- **Voicemail settings form** — PIN validation with counter (4-6 digits), section icons, toggle dimming, save checkmark animation, greeting type icons, human-readable duration and retention helpers.
- **Invite member dialog** — Email chip animations, submission progress ("Sending 1 of 3..."), invalid email feedback, header icon, max recipients hint, role change highlight.
- **Voicemail message list** — AlertDialog for single/bulk deletes, row striping, timestamp tooltips, pulse unread indicator, selected count badge.
- **Fax message detail** — Status-aware card border, US phone formatting, font-medium values, page count badge, file size on download buttons.
- **Location delete dialog** — Cancel button added, AlertTriangle icon.
- **Device actions** — Proper AlertDialogAction/Cancel in destructive confirm.

## v0.60.0 (2026-04-30)

### Improved
- **Voicemail message list** — AlertDialog confirmation for single and bulk deletes, row hover and alternating stripes, timestamp tooltips with full date, pulse animation on unread indicator, selected count badge, disabled bulk buttons when nothing selected.
- **Fax message detail** — Switched delete Dialog to AlertDialog (prevents accidental dismissal), status-aware top border color (green/amber/red), US phone formatting with parentheses, font-medium values in detail grid, page count badge on document preview, file size on download buttons.

## v0.59.0 (2026-04-30)

### Improved
- **Voicemail settings form** — PIN validation with character counter (4-6 digits, numeric only), section icons (Settings2/BellRing/Wrench), toggle description dimming when off, save success animation with checkmark, greeting type icons in select (Volume2/Mic/User), human-readable duration helpers for max length and retention period.
- **Invite member dialog** — Email chip entrance animations, submission progress counter ("Sending 1 of 3..."), invalid email XCircle feedback, UserPlus header icon, max recipients hint, role change highlight animation on permission card.

## v0.58.0 (2026-04-30)

### Improved
- **Active sessions** — AlertDialog for revoke-all, inline single-session revoke confirmation with auto-revert, tooltips on expiry timestamps, session count badge, IP address display, colored device icons, hover highlights, and refresh button.
- **Admin charts** — period toggle (7d/30d/90d), card descriptions, total summary counters, period-filtered data, primary color consistency, increased chart height, animation duration, cursor line on hover, and pulse skeleton loading.
- **Admin quick actions** — grouped sections (Users & Teams/System/Support) with separators, staggered entrance animation, active route highlighting, keyboard shortcut hints, action count description, and compact mode with show-all toggle.

## v0.57.0 (2026-04-30)

### Improved
- **Admin team table** — row hover and striping, active status dots, relative dates with tooltips, Users icon on member counts, total in header, and clickable rows.
- **Top users card** — ranked numbers with gold/silver/bronze, hover highlights, trend arrow for active users, clickable rows linking to user detail, graded progress bar colors, and subtitle.
- **User activity timeline** — colored timeline dots by action type, hover highlights, expandable details toggle, show-more pagination, filter pills (All/Logins/Changes/Security), and EmptyState.
- **Recent activity feed** — real notification data integration, relative timestamps, hover ChevronRight, clickable rows, scrollable max-height, dividers between items, and empty state.
- **Organization quick links** — hover scale, staggered entrance animation, ChevronRight slide, Compass section icon, active route highlighting, and keyboard hints.
- **Feature areas grid** — hover scale, staggered entrance, pulse shimmer on loading, zero-count styling, count fade-in, saturated icon bg on hover, and bottom border accent.

## v0.56.0 (2026-04-30)

### Improved
- **Extension table** — AlertDialog delete, row hover and striping, selected row highlight, active status dots, total count in header, result count text, Settings icon on action button, and Phone icon empty state.
- **Team list** — sort dropdown (name/members), grid/list view toggle, inactive team badge, relative created dates, result count in header, and "Create Team" placeholder card with dashed border.
- **Team members** — AlertDialog remove confirmation with spinner, search/filter by name or email, role filter buttons, member count per role breakdown, relative invitation dates, resend invitation button, and filtered empty state.
- **Team settings** — AlertDialog delete with consequences list, character counters (100/500), unsaved changes banner with Save/Discard, Settings and AlertTriangle icons, name field description, and form reset on save.

## v0.55.0 (2026-04-30)

### Improved
- **Join team dialog** — UserPlus header icon, user info summary card, team count label, description snippets in select, visual role cards instead of dropdown, success animation, and section separator.
- **Manage permissions dialog** — Lock header icon, CheckCircle2/XCircle permission icons with tooltips, feature-area icons (Phone/Printer/Monitor/LifeBuoy/CreditCard/BarChart3), row hover, team section cards, and per-team summary footer.
- **Manage roles dialog** — Shield header icon, violet role badges, inline remove confirmation with auto-revert, team row hover, role/team counts, ShieldOff/UsersRound empty state icons, spinner on assign, and success checkmark animation on role change.
- **Quick actions card** — keyboard shortcut hints on hover, "NEW" badge, team count badge, separator before admin actions, staggered entrance animation, and action count in description.
- **Getting started card** — numbered steps, dismiss with localStorage persistence, celebration state when complete, time estimates, and active-item highlight.
- **Quick stats** — hover scale, animated count fade-in, trend arrow for teams, zero-state styling with "Set up" text, hover ArrowRight icon, and pulse skeleton loading.

## v0.54.0 (2026-04-30)

### Improved
- **Phone number table** — switched delete to AlertDialog, US phone formatting, colored type icons (MapPin/Globe/Flag), active status dots, row hover and striping, copy number button, Loader2 on edit save, and result count text.
- **Fax number table** — row hover and striping, US phone formatting, active status dots, total count in header, copy number button, ArrowRight icon on Manage button, and result count text.
- **Fax message table** — relative timestamps with tooltip, row hover and striping, US phone formatting, total in header, result range text, AlertDialog delete confirmation, refresh button with spin animation, active filter count badge, clear-all filters button, and copy remote number.
- **Keyboard shortcuts dialog** — search/filter input with empty state, section separators, shortcut count in description, category icons (Compass/Layout/Zap), "+" between modifier keys, alternating row backgrounds, max-height scroll container, and "Press Esc to close" hint.

## v0.53.0 (2026-04-30)

### Improved
- **Ticket message** — reply button, copy message content, staff badge indicator, edited timestamp, thumbs-up reaction (local state), AlertDialog for delete confirmation, and left border color coding (blue staff/amber internal/gray regular).
- **Organization stats** — hover scale on stat cards, verified-users progress bar, trend indicators (up/down arrows), staggered entrance animation, click-to-navigate to admin pages, refresh button with spin animation, and last-updated timestamp.
- **Ticket table** — sortable column headers with direction arrows, relative timestamps with full-date tooltips, row hover highlight, priority colored dots, message count column, and improved empty state with contextual messaging.
- **Create tag page** — Tags icon, live slug preview with Hash icon, character counter (50), color picker with 8 swatches, required field indicator, description textarea (200 chars), and useBlocker for unsaved changes.

## v0.52.0 (2026-04-30)

### Improved
- **Ticket conversation** — "Jump to latest" floating button, visual date separators between days, system message filter toggle with hidden count badge, entrance animations, unread indicator line, and "Scroll to top" button.
- **Ticket detail header** — copy ticket number button, category quick-change dropdown, SLA timer indicator (green/amber/red by age), watch/unwatch toggle, separators between action groups, tooltips on dropdowns, and assignee avatar display.
- **Edit team dialog (admin)** — Users icon, field descriptions, character counters (50/500), required indicator, loading spinner, dirty state tracking, optional active status Switch, and section separators.
- **Delete team dialog (admin)** — switched to AlertDialog, AlertTriangle icon, type-to-confirm team name, deletion consequences summary, loading spinner, and red-tinted header.
- **Tags list page** — breadcrumbs, bulk selection with checkboxes and bulk delete, sortable Name/Slug columns, tag count in description, and row hover highlighting.

## v0.51.0 (2026-04-30)

### Improved
- **Global search** — recent searches history (localStorage), quick actions (Create Team/Device/Ticket), result count, colored type icons, clear input button, keyboard navigation hints footer, and match text highlighting.
- **Toggle user status dialog** — UserCheck/UserX icons, visual status transition indicator (Active → Inactive), impact summary bullet lists, loading spinner, tinted header background, and optional user name display.
- **Notification bell** — bell ring animation when unread, badge pulse animation on new notifications arrival, using CSS keyframes and ref-tracked previous count.
- **Device table** — sortable column headers with direction arrows, column visibility dropdown toggle, relative timestamps with full-date tooltips, row striping, hover highlight, and improved empty state with contextual messaging.

## v0.50.0 (2026-04-30)

### Improved
- **Profile info card** — gradient banner, role badge (Admin/Member), field descriptions and character counters, Cancel button, email copy button, unsaved changes amber dot, and success animation overlay.
- **Edit user dialog (admin)** — UserCog icon, user info header with email and verified status, field descriptions, administrator Switch toggle, loading spinner, dirty state tracking, and section separator.
- **Report issue tab** — category-specific icons in select, required field indicators, description character counter (max 2000), submission preview panel, dashed screenshot container, section separators, and total attachment size indicator.
- **Delete user dialog (admin)** — AlertTriangle icon, red-tinted header, deletion summary list (account/teams/sessions/OAuth), irreversibility warning with ShieldAlert, type-to-confirm email verification, and loading spinner.

## v0.49.0 (2026-04-30)

### Improved
- **Help menu** — added Keyboard Shortcuts, What's New (with "New" badge), and Contact Support menu items with separators and keyboard shortcut hints.
- **Help dialog** — `defaultTab` prop support for opening directly to shortcuts or resources tab.
- **Resources tab** — grouped into Documentation and Community sections with headers, colored icon backgrounds, search/filter input, "Updated" badge on API docs, and hover card effects.
- **Nav projects** — colored team avatars with initials, 5-item limit with collapsible "Show more", optional member count badge, active state highlighting, and hover transitions.
- **Theme toggle** — three-state cycle (light/dark/system) with rotation animation, tooltip, pulse effect on change, and colored dot indicator.
- **About page** — hero section with gradient background and CTAs, product feature cards with colored icons, team member cards, contact section, staggered framer-motion entrance animations, and styled footer.

## v0.48.0 (2026-04-30)

### Improved
- **Ticket priority badge** — priority-specific icons (ArrowDown/Minus/ArrowUp/AlertTriangle), descriptive tooltips, pulse animation on urgent, and compact icon-only size variant.
- **Ticket status badge** — status-specific icons (Circle/Clock/User/Headphones/CheckCircle/XCircle), colored dot indicator, descriptive tooltips, and entrance animation.
- **Team permissions** — feature-area icons, Reset button, unsaved changes banner, Select All/Deselect All per role, shadcn Checkbox component, and summary row with enabled counts.
- **Phone number card** — US phone formatting, copy button, colored type icons (MapPin/Globe/Flag), extension assignment indicator, hover scale, active status left border, relative timestamps, and AlertDialog for delete.
- **Markdown renderer** — code block copy button, syntax highlighting classes, blockquote styling with left border, responsive striped tables, external link icons, task list checkbox rendering, and heading anchor links.

## v0.47.0 (2026-04-30)

### Improved
- **Fax message detail** — relative timestamps with tooltips, copy buttons on remote number and message ID, error Alert banner for failed messages, formatted phone numbers, resend button for failed outbound, email delivery badges, section separators, and print button.
- **Attachment preview** — file info bar, image zoom controls (50%-300%), fit-to-window button, prev/next navigation with keyboard arrows, loading skeleton, entrance animations, and keyboard shortcut hints bar.
- **Create extension dialog** — Phone icon, field descriptions, numeric-only validation, display name character counter, required field indicator, loading spinner, active status Switch toggle, and success toast.
- **Create phone number dialog** — Hash icon, field descriptions, E.164 format validation, required indicator, type-specific icons in select, loading spinner, live preview section, and success toast.

## v0.46.0 (2026-04-30)

### Improved
- **Device actions** — 2x2 card grid layout with colored icon backgrounds, section grouping (Operations/Management), AlertDialog for destructive actions, descriptive subtitles, tooltips, and optional "last rebooted" timestamp.
- **DND quick toggle** — pulsing red dot indicator when active, loading spinner, red-tinted background, DND mode in tooltip, compact icon-only mode, and keyboard shortcut ("d" key).
- **Email route editor** — inline email validation indicator, test route button with toast, animated count badge, enhanced empty state with MailPlus icon, delete confirmation AlertDialog, active/inactive colored dot counts, and bulk activate/deactivate toggle.
- **Email route row** — Switch toggles replacing badge buttons, colored mail icon, hover highlighting, status toggle toasts, copy email button, inline delete confirmation with auto-revert timer, row entrance animation, and test route button.

## v0.45.0 (2026-04-30)

### Improved
- **Device line config** — unsaved changes banner, Switch toggle for active status, drag handle indicators, line count in header, colored type badges, styled empty state with Cable icon, remove confirmation AlertDialog, and section separators.
- **Attachment list** — header with Paperclip icon and count, attachments grouped by type, image thumbnails as preview tiles, total file size summary, hover scale effects, type-based color tinting (purple/red/gray), and "Download all" button.
- **Attachment upload** — file type and size validation with toast errors, file-type-specific icons, upload pulse animation, animated drag-over styling, compact mode file count badge, "Clear all" button, and colored left borders by file type.
- **Ticket system messages** — action-type parsing with contextual icons and colors (status/priority/assignment/close/reopen), relative timestamps, horizontal divider lines flanking the pill, entrance fade animation, and actor name display.

## v0.44.0 (2026-04-30)

### Improved
- **Ticket reply form** — character counter, Ctrl+Enter keyboard shortcut, success animation with green checkmark, user avatar in header, left border accent, discard button with confirmation for long messages, and keyboard hint.
- **Markdown editor** — word count display, fullscreen toggle, strikethrough and horizontal rule toolbar buttons, drag-over file drop indicator with overlay, and active formatting state detection highlighting toolbar buttons.
- **Fax message list** — relative timestamps with full-date tooltips, debounced search by remote number, bulk selection with checkboxes and bulk delete, row hover highlighting, failed-status error tooltips, refresh button, result count text, and styled page count badges.
- **Fax number card** — US phone number formatting, actual email route count display, message count with icon, animated status dot, hover scale effect, relative created date, quick Send Fax button, and warning indicator for missing email routes.

## v0.43.0 (2026-04-30)

### Improved
- **Extension settings form** — unsaved changes banner, Switch toggle for active status, field descriptions, phone number display, relative timestamps, Cancel/Reset button, and section separators.
- **DND schedule picker** — header with CalendarClock icon, pill-shaped day toggles with color transitions, weekly total hours indicator, tooltip time ranges on schedule bars, matching-preset checkmarks, clear schedule button, and section separators.
- **Device card** — colored icon backgrounds by device type, pulse animation for provisioning status, line count badge, hover scale effect, relative timestamps, colored top border by active status, firmware version badge, and copy MAC button on hover.
- **Ticket list item** — category icons (HelpCircle/Bug/Lightbulb/Wrench), message count indicator, relative timestamps, hover ChevronRight, unread left border accent, and SLA clock indicator for urgent/high open tickets.

## v0.42.0 (2026-04-30)

### Improved
- **DND settings form** — visual DND status banner with color coding, Switch toggle replacing checkbox, selectable mode cards (Do Not Disturb/Allow List/Schedule), tag-style allow list chips, and section separators.
- **Forwarding rule editor** — illustrated empty state, rule type icons (Always/Busy/No Answer/Unreachable), add-rule Dialog with condition-aware fields, card-style rule rows with group-hover transitions, and priority badges.
- **Home stat cards** — trend indicators (up/down/neutral arrows with colors), hover scale animation, clickable cards navigating to relevant sections, and staggered framer-motion entrance.
- **Home recent activity card** — action-type icons with semantic colors (create/update/delete/login), resource type badges, "View all activity" link for admins, and enhanced empty state.
- **Home teams card** — colored team avatars from name hash, member count display, active team check indicator, and hover animation effects.

## v0.41.0 (2026-04-30)

### Improved
- **Voicemail player** — volume control with mute toggle, playback speed (1x/1.5x/2x), draggable progress knob, keyboard controls (space/arrows), and styled container.
- **MFA profile section** — visual status banner (green Protected / amber Not Protected), backup codes progress bar with color thresholds, info tooltips, and "enabled on" date display.
- **Invite member dialog** — toast notifications, bulk email invitations with removable badges, email validation checkmark, loading spinner, and role permissions preview card.
- **Active sessions** — current session "This device" highlight with green badge, location info with MapPin, sessions grouped by device type (Desktop/Mobile/Tablet), compact relative timestamps, and revoke-all confirmation with count.

## v0.40.0 (2026-04-30)

### Improved
- **Team switcher** — colored team avatars, active team checkmark, team count subtitle, search filter for 5+ teams, and "Manage teams" link.
- **Error boundary** — copy error details button, framer-motion entrance, deterministic error reference code (ERR-XXXXXXXX), collapsible stack trace, and gradient background.
- **Email verification banner** — 60-second resend countdown timer, slide-down entrance animation, pulsing mail icon, and session-dismissible X button.
- **Password change card** — real-time confirm password match indicator with animated icons, and success state animation with auto-reset after password update.

## v0.39.0 (2026-04-30)

### Improved
- **NavUser dropdown** — Settings and Notifications links, role badge (Admin/Member), keyboard shortcut hint (Cmd/Ctrl+K), and online status dot on avatar.
- **Personal info form** — phone number auto-formatting, real-time username validation (alphanumeric + underscores), character counters, success checkmark animation, and Cancel button.
- **Voicemail settings form** — field descriptions, grouped sections (General/Notifications/Advanced) with separators, unsaved changes banner, "Reset to defaults" button, and Switch components for toggles.
- **Connected accounts** — provider icons with colored backgrounds, connected/last-login timestamps, disconnect confirmation dialog, and empty state with OAuth link buttons.

## v0.38.0 (2026-04-30)

### Improved
- **MFA TOTP input** — individual 6-digit boxes with auto-advance, backspace navigation, paste support, and dash separator.
- **MFA setup dialog** — 3-step progress indicator, ShieldCheck icon, and collapsible "Can't scan?" manual entry toggle.
- **MFA disable dialog** — amber security warning, ShieldOff icon, and destructive button styling.
- **Backup codes display** — download-as-text button, amber "won't be shown again" warning, and per-code hover copy.
- **Team activity** — per-action-type icons and colors, relative timestamps, loading skeletons, empty state, and paginated "Load more" button.
- **Help dialog** — keyboard shortcuts section (Cmd+K, ?, Esc), quick action links, staggered animations, and version footer.

## v0.37.0 (2026-04-30)

### Improved
- **Sidebar** — live unread notification count badge on the Notifications nav item, auto-refreshes every 30 seconds.
- **404 page** — framer-motion entrance animation, floating icon, quick-link buttons (Home/Support/Settings), and gradient background.
- **Privacy policy page** — table of contents with anchor links, numbered sections, new "Your Rights", "Cookies", and "Updates" sections, last-updated date, cross-link to Terms, and scroll-to-top button with animations.
- **Terms of service page** — table of contents with anchor links, numbered sections, new "Account Responsibilities", "Intellectual Property", and "Changes" sections, last-updated date, cross-link to Privacy, and scroll-to-top button with animations.

## v0.36.0 (2026-04-30)

### Added
- **Team edit page** (`/teams/:id/edit`) — edit name, description, and tags with dirty-field diffing, unsaved changes blocker, and breadcrumbs. New `useTeam` and `useUpdateTeam` hooks.
- **Location edit page** (`/locations/:id/edit`) — edit name, description, and address fields (for addressed type) with dirty-field diffing and unsaved changes blocker.

### Improved
- **Landing page** — feature highlight cards (Voice, Fax, Devices, Support), stat counters row, prominent CTA buttons, and staggered framer-motion entrance animations.
- **Team invitation accept page** — gradient background, framer-motion card entrance, team description and member count display, and animated status icons with spring transitions.
- **Team detail page** — added Edit button in header linking to edit page.
- **Location detail page** — added Edit Page link alongside existing inline Quick Edit button.

## v0.35.0 (2026-04-30)

### Improved
- **Locations list page** — table layout with sortable Name/Type columns, checkbox bulk delete, address summary column, sub-location count, truncated description, row-click navigation, and result counts.
- **Locations detail page** — two-column layout with metadata sidebar (ID copy, relative timestamps), sectioned info card with address section, and Danger Zone delete card.
- **Locations create form** — required field indicators, field description hints, character counters with max-length validation (100/500), and unsaved changes blocker with AlertDialog.
- **Notifications page** — notification preferences section with email master toggle and per-category toggles (system/team/ticket/device/voice/fax), bulk "Delete all read" button, and improved empty state with BellOff illustration.
- **Organization page** — copy buttons on email/phone/website fields, page header gradient, Active status badge, and Organization Details metadata card with ID/slug/member/team counts.

## v0.34.0 (2026-04-30)

### Improved
- **Device edit page** — MAC auto-formatting, IP validation, device type icons, required indicators, field descriptions, section separators, and unsaved changes blocker.
- **Auth pages** — branded icon headers, card layouts with motion animations, input icons (mail/lock/user), password visibility toggles, "Remember me" checkbox on login, OAuth buttons above form with divider, spinners during loading, and consistent styling across login, signup, forgot/reset password, MFA challenge, and email verification.

## v0.33.0 (2026-04-30)

### Improved
- **Connection edit page** — ported all create-page improvements: required indicators, field hints, inline validation, auth change warning, credential security note, type icons, sidebar cards, unsaved changes blocker.
- **Admin system page** — health banner, service status grid with per-service icons, live-ticking uptime, worker queue details with per-queue stats, auto-refresh toggle (30s), and last-refreshed indicator.

## v0.32.0 (2026-04-30)

### Improved
- **Support ticket create page** — category icon grid, priority radio cards with color coding, field descriptions, response time SLA sidebar, unsaved changes warning dialog, subject/description length validation.
- **Device create page** — MAC address auto-formatting, IP address validation, device type icons, required field indicators, field descriptions, unsaved changes blocker, and section separators.

## v0.31.0 (2026-04-30)

### Added
- **Gateway lookup page** (`/gateway`) — tabbed UI for phone number, extension, and device lookups across all connections. Results grouped by source with status badges and recursive data rendering. New React Query hooks and sidebar nav item.

### Improved
- **Connections create page** — required field indicators, field descriptions, inline validation (host URL, port range), auth type change warning dialog, credential security note with lock icon, unsaved changes blocker, connection type icons in dropdown, and security sidebar card.

## v0.30.0 (2026-04-30)

### Improved
- **Voice index page** — breadcrumbs, status overview with active/inactive breakdown and progress bars, colored quick action icons, stat card refinements showing "X active of Y", staggered section animations.
- **Teams create page** — required field indicators, form field descriptions with max-length validation, styled tags section, improved sidebar tips, and disabled submit when name is empty.

## v0.29.0 (2026-04-30)

### Improved
- **Voice DND page** — breadcrumbs with extension name, large visual DND status card with color-coded background and oversized toggle, quick summary cards for mode/schedule/allowed callers, loading/error states.
- **Fax send page** — sectioned form layout (From/To/Content), drag-and-drop file upload with type/size validation, phone number formatting, text content tab with live preview, confirmation dialog with summary, success state with view-message link.

## v0.28.0 (2026-04-30)

### Improved
- **Voice forwarding page** — breadcrumbs with extension name, rules table with priority/condition/destination/timeout, inline enabled toggles, add-rule dialog with condition-aware fields, delete confirmation, and empty/loading/error states.
- **Admin team detail page** — hero section with gradient avatar and status badge, organized sections (Info, Statistics, Members with avatars, Admin Actions with toggle, Invitations, Danger Zone), copy buttons, and relative timestamps.

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
