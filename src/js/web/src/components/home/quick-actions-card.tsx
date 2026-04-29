import { Link } from "@tanstack/react-router"
import { ChevronRight, type LucideIcon, Plus, Settings, ShieldCheck, Tag, Users } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"

interface QuickAction {
  key: string
  label: string
  description: string
  to: string
  icon: LucideIcon
  iconBgClassName: string
  iconTextClassName: string
}

const defaultActions: QuickAction[] = [
  {
    key: "create-team",
    label: "Create a new team",
    description: "Start collaborating",
    to: "/teams/new",
    icon: Plus,
    iconBgClassName: "bg-primary/10 group-hover:bg-primary",
    iconTextClassName: "text-primary group-hover:text-primary-foreground",
  },
  {
    key: "browse-teams",
    label: "Browse all teams",
    description: "View your workspaces",
    to: "/teams",
    icon: Users,
    iconBgClassName: "bg-blue-500/10 group-hover:bg-blue-500",
    iconTextClassName: "text-blue-600 dark:text-blue-400 group-hover:text-white dark:group-hover:text-white",
  },
  {
    key: "manage-tags",
    label: "Manage tags",
    description: "Organize resources",
    to: "/admin",
    icon: Tag,
    iconBgClassName: "bg-emerald-500/10 group-hover:bg-emerald-500",
    iconTextClassName: "text-emerald-600 dark:text-emerald-400 group-hover:text-white dark:group-hover:text-white",
  },
  {
    key: "edit-profile",
    label: "Edit your profile",
    description: "Manage account settings",
    to: "/profile",
    icon: Settings,
    iconBgClassName: "bg-orange-500/10 group-hover:bg-orange-500",
    iconTextClassName: "text-orange-600 dark:text-orange-400 group-hover:text-white dark:group-hover:text-white",
  },
]

const adminActions: QuickAction[] = [
  {
    key: "admin-console",
    label: "Admin console",
    description: "Manage platform",
    to: "/admin",
    icon: ShieldCheck,
    iconBgClassName: "bg-violet-500/10 group-hover:bg-violet-500",
    iconTextClassName: "text-violet-600 dark:text-violet-400 group-hover:text-white dark:group-hover:text-white",
  },
]

interface QuickActionsCardProps {
  isSuperuser?: boolean
}

export function QuickActionsCard({ isSuperuser }: QuickActionsCardProps) {
  const actions = isSuperuser ? [...defaultActions, ...adminActions] : defaultActions

  return (
    <Card className="border-border/40 bg-linear-to-br from-muted/30 to-muted/10">
      <CardHeader className="space-y-1 pb-3">
        <CardTitle className="text-lg">Quick Actions</CardTitle>
        <CardDescription>Common tasks</CardDescription>
      </CardHeader>
      <CardContent className="space-y-1.5">
        {actions.map((action) => (
          <Link
            key={action.key}
            to={action.to}
            className="group flex items-center gap-3 rounded-lg bg-background/60 p-3 transition-all hover:bg-background hover:shadow-sm"
          >
            <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg transition-colors ${action.iconBgClassName} ${action.iconTextClassName}`}>
              <action.icon className="h-4 w-4" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium">{action.label}</p>
              <p className="text-xs text-muted-foreground">{action.description}</p>
            </div>
            <ChevronRight className="h-4 w-4 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-foreground" />
          </Link>
        ))}
      </CardContent>
    </Card>
  )
}
