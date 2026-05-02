import { Link } from "@tanstack/react-router"
import { Bell, ChevronRight, Headset, type LucideIcon, Monitor, Plus, Settings, ShieldCheck, Tag, Users } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"

interface QuickAction {
  key: string
  label: string
  description: string
  to: string
  icon: LucideIcon
  iconBgClassName: string
  iconTextClassName: string
  shortcut?: string
  isNew?: boolean
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
    shortcut: "T",
  },
  {
    key: "manage-devices",
    label: "Manage devices",
    description: "Phones, computers & hardware",
    to: "/devices",
    icon: Monitor,
    iconBgClassName: "bg-blue-500/10 group-hover:bg-blue-500",
    iconTextClassName: "text-blue-600 dark:text-blue-400 group-hover:text-white dark:group-hover:text-white",
  },
  {
    key: "submit-ticket",
    label: "Submit a support ticket",
    description: "Get help from the team",
    to: "/support/new",
    icon: Headset,
    iconBgClassName: "bg-amber-500/10 group-hover:bg-amber-500",
    iconTextClassName: "text-amber-600 dark:text-amber-400 group-hover:text-white dark:group-hover:text-white",
  },
  {
    key: "view-notifications",
    label: "View notifications",
    description: "Check unread alerts",
    to: "/notifications",
    icon: Bell,
    iconBgClassName: "bg-rose-500/10 group-hover:bg-rose-500",
    iconTextClassName: "text-rose-600 dark:text-rose-400 group-hover:text-white dark:group-hover:text-white",
  },
  {
    key: "browse-teams",
    label: "Browse all teams",
    description: "View your workspaces",
    to: "/teams",
    icon: Users,
    iconBgClassName: "bg-cyan-500/10 group-hover:bg-cyan-500",
    iconTextClassName: "text-cyan-600 dark:text-cyan-400 group-hover:text-white dark:group-hover:text-white",
    shortcut: "D",
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
    shortcut: "P",
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
    shortcut: "A",
  },
]

interface QuickActionsCardProps {
  isSuperuser?: boolean
  teamCount?: number
}

export function QuickActionsCard({ isSuperuser, teamCount }: QuickActionsCardProps) {
  const actions = isSuperuser ? [...defaultActions, ...adminActions] : defaultActions

  return (
    <Card className="border-border/40 bg-linear-to-br from-muted/30 to-muted/10">
      <CardHeader className="space-y-1 pb-3">
        <CardTitle className="text-lg">Quick Actions</CardTitle>
        <CardDescription>{actions.length} actions available</CardDescription>
      </CardHeader>
      <CardContent className="space-y-1.5">
        {actions.map((action, index) => (
          <div key={action.key}>
            {isSuperuser && action.key === "admin-console" && <Separator className="my-2" />}
            <Link
              to={action.to}
              className="animate-in fade-in slide-in-from-left-2 group flex items-center gap-3 rounded-lg bg-background/60 p-3 fill-mode-both transition-all hover:bg-background hover:shadow-sm"
              style={{ animationDelay: `${index * 50}ms` }}
            >
              <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg transition-colors ${action.iconBgClassName} ${action.iconTextClassName}`}>
                <action.icon className="h-4 w-4" />
              </div>
              <div className="min-w-0 flex-1">
                <span className="flex items-center text-sm font-medium">
                  {action.label}
                  {action.isNew && (
                    <Badge variant="default" className="ml-2 h-4 text-[9px]">
                      NEW
                    </Badge>
                  )}
                  {action.key === "browse-teams" && teamCount !== undefined && teamCount > 0 && (
                    <Badge variant="secondary" className="ml-2 h-4 text-[9px]">
                      {teamCount}
                    </Badge>
                  )}
                </span>
                <p className="text-xs text-muted-foreground">{action.description}</p>
              </div>
              {action.shortcut && (
                <kbd className="ml-auto hidden rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground group-hover:inline">
                  {action.shortcut}
                </kbd>
              )}
              <ChevronRight className="h-4 w-4 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-foreground" />
            </Link>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}
