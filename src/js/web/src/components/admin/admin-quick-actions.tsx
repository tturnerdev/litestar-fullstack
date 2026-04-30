import { useState } from "react"
import { Link, useLocation } from "@tanstack/react-router"
import { ChevronRight, FileText, Monitor, Phone, ShieldCheck, Ticket, UserPlus, Users } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"

const actionGroups = [
  {
    label: "Users & Teams",
    actions: [
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
        label: "Manage Roles",
        description: "Configure permissions",
        icon: ShieldCheck,
        color: "text-violet-600 dark:text-violet-400",
        bg: "bg-violet-500/10",
        hoverBg: "group-hover/action:bg-violet-500",
        to: "/admin/teams",
      },
    ],
  },
  {
    label: "System",
    actions: [
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
    ],
  },
  {
    label: "Support",
    actions: [
      {
        label: "Support Tickets",
        description: "View open tickets",
        icon: Ticket,
        color: "text-orange-600 dark:text-orange-400",
        bg: "bg-orange-500/10",
        hoverBg: "group-hover/action:bg-orange-500",
        to: "/admin/support",
      },
    ],
  },
]

const allActions = actionGroups.flatMap((g) => g.actions)
const COMPACT_LIMIT = 5

export function AdminQuickActions() {
  const location = useLocation()
  const [expanded, setExpanded] = useState(false)

  const visibleCount = expanded ? allActions.length : COMPACT_LIMIT
  let globalIndex = 0

  return (
    <Card>
      <CardHeader>
        <CardTitle>Quick Actions</CardTitle>
        <CardDescription>{allActions.length} actions</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {actionGroups.map((group, groupIdx) => {
          const groupActions = group.actions.filter(() => {
            return globalIndex < visibleCount
          })

          if (groupActions.length === 0) return null

          const startIndex = globalIndex

          return (
            <div key={group.label}>
              {groupIdx > 0 && startIndex < visibleCount && <Separator className="mb-3" />}
              <p className="mb-1.5 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/60">
                {group.label}
              </p>
              <div className="space-y-1">
                {group.actions.map((action) => {
                  const currentIndex = globalIndex
                  if (currentIndex >= visibleCount) return null
                  globalIndex++

                  const Icon = action.icon
                  const isActive = location.pathname.startsWith(action.to)
                  const kbdNumber = currentIndex < 7 ? currentIndex + 1 : null

                  return (
                    <Link
                      key={action.label}
                      to={action.to}
                      className={`group/action flex items-center gap-3 rounded-lg px-3 py-2.5 transition-all hover:bg-muted/60 animate-in fade-in slide-in-from-left-2 ${
                        isActive ? "border-l-2 border-primary bg-primary/5" : ""
                      }`}
                      style={{ animationDelay: `${currentIndex * 40}ms`, animationFillMode: "backwards" }}
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
                      {kbdNumber !== null && (
                        <kbd className="ml-auto hidden rounded border border-border bg-muted px-1 py-0.5 font-mono text-[10px] text-muted-foreground group-hover/action:inline">
                          {kbdNumber}
                        </kbd>
                      )}
                      <ChevronRight className="h-4 w-4 text-muted-foreground/40 transition-transform group-hover/action:translate-x-0.5 group-hover/action:text-muted-foreground" />
                    </Link>
                  )
                })}
              </div>
            </div>
          )
        })}
        {allActions.length > COMPACT_LIMIT && (
          <button
            onClick={() => setExpanded((prev) => !prev)}
            className="w-full rounded-md px-3 py-1.5 text-center text-xs font-medium text-muted-foreground transition-colors hover:bg-muted/60 hover:text-foreground"
          >
            {expanded ? "Show less" : `Show all (${allActions.length})`}
          </button>
        )}
      </CardContent>
    </Card>
  )
}
