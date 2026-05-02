import { Link, useRouterState } from "@tanstack/react-router"
import { Button } from "@/components/ui/button"

const navItems = [
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
  { label: "Audit log", to: "/admin/audit" },
  { label: "System", to: "/admin/system" },
] as const

export function AdminNav() {
  const pathname = useRouterState({
    select: (state) => state.location.pathname,
  })

  return (
    <div className="flex flex-wrap gap-2">
      {navItems.map((item) => {
        const isActive = pathname === item.to || (item.to !== "/admin" && pathname.startsWith(item.to))
        return (
          <Button key={item.to} asChild variant={isActive ? "default" : "outline"} size="sm">
            <Link to={item.to}>{item.label}</Link>
          </Button>
        )
      })}
    </div>
  )
}
