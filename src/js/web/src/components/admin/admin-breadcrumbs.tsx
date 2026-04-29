import { Link, useRouterState } from "@tanstack/react-router"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"

/** Known second-level admin sections mapped from URL segment to display label. */
const sectionLabels: Record<string, string> = {
  users: "Users",
  teams: "Teams",
  devices: "Devices",
  voice: "Voice",
  fax: "Fax",
  support: "Support",
  audit: "Audit Log",
  system: "System",
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
  const afterAdmin = normalized.startsWith(adminPrefix)
    ? normalized.slice(adminPrefix.length)
    : ""
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
        {/* Root: Admin */}
        {crumbs.length === 0 ? (
          <BreadcrumbItem>
            <BreadcrumbPage>Admin</BreadcrumbPage>
          </BreadcrumbItem>
        ) : (
          <>
            <BreadcrumbItem>
              <BreadcrumbLink asChild>
                <Link to="/admin">Admin</Link>
              </BreadcrumbLink>
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
