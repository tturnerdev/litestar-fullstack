import { Link } from "@tanstack/react-router"
import { ChevronRight, FileText, Monitor, Phone, ShieldCheck, Ticket, UserPlus, Users } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

const actions = [
  {
    label: "Create User",
    description: "Add a new account",
    icon: UserPlus,
    color: "text-emerald-600 dark:text-emerald-400",
    bg: "bg-emerald-500/10",
    hoverBg: "group-hover/action:bg-emerald-500",
    to: "/admin/users",
  },
  {
    label: "Manage Teams",
    description: "Configure workspaces",
    icon: Users,
    color: "text-blue-600 dark:text-blue-400",
    bg: "bg-blue-500/10",
    hoverBg: "group-hover/action:bg-blue-500",
    to: "/admin/teams",
  },
  {
    label: "View Audit Log",
    description: "Review all events",
    icon: FileText,
    color: "text-amber-600 dark:text-amber-400",
    bg: "bg-amber-500/10",
    hoverBg: "group-hover/action:bg-amber-500",
    to: "/admin/audit",
  },
  {
    label: "Manage Roles",
    description: "Configure permissions",
    icon: ShieldCheck,
    color: "text-violet-600 dark:text-violet-400",
    bg: "bg-violet-500/10",
    hoverBg: "group-hover/action:bg-violet-500",
    to: "/admin/teams",
  },
  {
    label: "Manage Devices",
    description: "View provisioned devices",
    icon: Monitor,
    color: "text-cyan-600 dark:text-cyan-400",
    bg: "bg-cyan-500/10",
    hoverBg: "group-hover/action:bg-cyan-500",
    to: "/admin/devices",
  },
  {
    label: "Voice & Numbers",
    description: "Phone number management",
    icon: Phone,
    color: "text-pink-600 dark:text-pink-400",
    bg: "bg-pink-500/10",
    hoverBg: "group-hover/action:bg-pink-500",
    to: "/admin/voice",
  },
  {
    label: "Support Tickets",
    description: "View open tickets",
    icon: Ticket,
    color: "text-orange-600 dark:text-orange-400",
    bg: "bg-orange-500/10",
    hoverBg: "group-hover/action:bg-orange-500",
    to: "/admin/support",
  },
] as const

export function AdminQuickActions() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Quick Actions</CardTitle>
      </CardHeader>
      <CardContent className="space-y-1">
        {actions.map((action) => {
          const Icon = action.icon
          return (
            <Link
              key={action.label}
              to={action.to}
              className="group/action flex items-center gap-3 rounded-lg px-3 py-2.5 transition-all hover:bg-muted/60"
            >
              <div
                className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${action.bg} ${action.color} transition-colors ${action.hoverBg} group-hover/action:text-white`}
              >
                <Icon className="h-3.5 w-3.5" />
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium leading-tight">{action.label}</p>
                <p className="text-[11px] text-muted-foreground">{action.description}</p>
              </div>
              <ChevronRight className="h-4 w-4 text-muted-foreground/40 transition-transform group-hover/action:translate-x-0.5 group-hover/action:text-muted-foreground" />
            </Link>
          )
        })}
      </CardContent>
    </Card>
  )
}
