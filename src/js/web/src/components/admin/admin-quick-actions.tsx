import { Link } from "@tanstack/react-router"
import { ChevronRight, FileText, ShieldCheck, UserPlus, Users } from "lucide-react"
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
    label: "Create Team",
    description: "Set up a workspace",
    icon: Users,
    color: "text-blue-600 dark:text-blue-400",
    bg: "bg-blue-500/10",
    hoverBg: "group-hover/action:bg-blue-500",
    to: "/teams/new",
  },
  {
    label: "View Audit Logs",
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
] as const

export function AdminQuickActions() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Quick Actions</CardTitle>
      </CardHeader>
      <CardContent className="space-y-1.5">
        {actions.map((action) => {
          const Icon = action.icon
          return (
            <Link
              key={action.label}
              to={action.to}
              className="group/action flex items-center gap-3 rounded-lg bg-background/60 p-3 transition-all hover:bg-background hover:shadow-sm"
            >
              <div
                className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${action.bg} ${action.color} transition-colors ${action.hoverBg} group-hover/action:text-white`}
              >
                <Icon className="h-4 w-4" />
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">{action.label}</p>
                <p className="text-xs text-muted-foreground">{action.description}</p>
              </div>
              <ChevronRight className="h-4 w-4 text-muted-foreground/50 transition-transform group-hover/action:translate-x-0.5 group-hover/action:text-foreground" />
            </Link>
          )
        })}
      </CardContent>
    </Card>
  )
}
