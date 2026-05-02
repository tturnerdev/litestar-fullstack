import { Link, useRouterState } from "@tanstack/react-router"
import {
  Breadcrumb,
  BreadcrumbDropdownLink,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
  type BreadcrumbSibling,
} from "@/components/ui/breadcrumb"

/** Known second-level admin sections mapped from URL segment to display label. */
const sectionLabels: Record<string, string> = {
  users: "Users",
  teams: "Teams",
  devices: "Devices",
  "device-templates": "Device Templates",
  voice: "Voice",
  "music-on-hold": "Music on Hold",
  fax: "Fax",
  support: "Support",
  gateway: "Gateway",
  "bulk-import": "Bulk Import",
  tasks: "Tasks",
  roles: "Roles & Permissions",
  audit: "Audit Log",
  system: "System",
}

/** All admin sibling pages available from the "Admin" breadcrumb dropdown. */
const adminSiblings: BreadcrumbSibling[] = [
  { label: "Dashboard", to: "/admin" },
  { label: "Users", to: "/admin/users" },
  { label: "Teams", to: "/admin/teams" },
  { label: "Devices", to: "/admin/devices" },
  { label: "Device Templates", to: "/admin/device-templates" },
  { label: "Voice", to: "/admin/voice" },
  { label: "Music on Hold", to: "/admin/music-on-hold" },
  { label: "Fax", to: "/admin/fax" },
  { label: "Support", to: "/admin/support" },
  { label: "Gateway", to: "/admin/gateway" },
  { label: "Bulk Import", to: "/admin/bulk-import" },
  { label: "Tasks", to: "/admin/tasks" },
  { label: "Roles & Permissions", to: "/admin/roles" },
  { label: "Audit Log", to: "/admin/audit" },
  { label: "System", to: "/admin/system" },
]

function renderAdminLink(sibling: BreadcrumbSibling) {
  return <Link to={sibling.to}>{sibling.label}</Link>
}

interface AdminBreadcrumbsProps {
  /** Override the label shown for the current (last) breadcrumb segment.
   *  Useful for detail pages where you want to show an entity name
   *  (e.g. "John Smith") instead of a raw ID. */
  currentLabel?: string
}

export function AdminBreadcrumbs({ currentLabel }: AdminBreadcrumbsProps) {
  const pathname = useRouterState({
    select: (state) => state.location.pathname,
  })

  // Strip trailing slash and split into segments after "/admin"
  const normalized = pathname.replace(/\/$/, "")
  const adminPrefix = "/admin"
  const afterAdmin = normalized.startsWith(adminPrefix) ? normalized.slice(adminPrefix.length) : ""
  const segments = afterAdmin.split("/").filter(Boolean)

  // Build crumb entries: [{ label, to }]
  // Always start with "Admin" pointing to /admin
  const crumbs: Array<{ label: string; to: string }> = []

  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i]
    const to = `${adminPrefix}/${segments.slice(0, i + 1).join("/")}`
    const isLast = i === segments.length - 1

    if (i === 0) {
      // Second-level: known section
      crumbs.push({ label: sectionLabels[segment] ?? segment, to })
    } else if (isLast && currentLabel) {
      // Detail page with a provided label
      crumbs.push({ label: currentLabel, to })
    } else {
      // Fallback for unknown deeper segments
      crumbs.push({ label: sectionLabels[segment] ?? segment, to })
    }
  }

  return (
    <Breadcrumb className="mb-2">
      <BreadcrumbList>
        {/* Root: Admin — with dropdown to all admin sub-pages */}
        {crumbs.length === 0 ? (
          <BreadcrumbItem>
            <BreadcrumbDropdownLink label="Admin" siblings={adminSiblings} renderLink={renderAdminLink} />
          </BreadcrumbItem>
        ) : (
          <>
            <BreadcrumbItem>
              <BreadcrumbDropdownLink label="Admin" siblings={adminSiblings} renderLink={renderAdminLink} />
            </BreadcrumbItem>

            {crumbs.map((crumb, idx) => {
              const isLast = idx === crumbs.length - 1
              return (
                <span key={crumb.to} className="contents">
                  <BreadcrumbSeparator />
                  <BreadcrumbItem>
                    {isLast ? (
                      <BreadcrumbPage>{crumb.label}</BreadcrumbPage>
                    ) : (
                      <BreadcrumbLink asChild>
                        <Link to={crumb.to}>{crumb.label}</Link>
                      </BreadcrumbLink>
                    )}
                  </BreadcrumbItem>
                </span>
              )
            })}
          </>
        )}
      </BreadcrumbList>
    </Breadcrumb>
  )
}
