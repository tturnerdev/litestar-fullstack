import { Link } from "@tanstack/react-router"
import { Activity, ArrowRight, LogIn, Pencil, Plus, Trash2, type LucideIcon } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import type { ActivityLogEntry } from "@/lib/generated/api"

function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSeconds = Math.floor(diffMs / 1000)
  const diffMinutes = Math.floor(diffSeconds / 60)
  const diffHours = Math.floor(diffMinutes / 60)
  const diffDays = Math.floor(diffHours / 24)

  if (diffSeconds < 60) return "just now"
  if (diffMinutes < 60) return `${diffMinutes}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  if (diffDays < 7) return `${diffDays}d ago`
  return date.toLocaleDateString()
}

function formatActionLabel(action: string): string {
  return action
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

interface ActionStyle {
  icon: LucideIcon
  color: string
  bgColor: string
}

function getActionStyle(action: string): ActionStyle {
  const lower = action.toLowerCase()

  if (lower.includes("create") || lower.includes("add")) {
    return { icon: Plus, color: "text-emerald-600 dark:text-emerald-400", bgColor: "bg-emerald-500/15" }
  }
  if (lower.includes("update") || lower.includes("edit") || lower.includes("modify")) {
    return { icon: Pencil, color: "text-blue-600 dark:text-blue-400", bgColor: "bg-blue-500/15" }
  }
  if (lower.includes("delete") || lower.includes("remove")) {
    return { icon: Trash2, color: "text-red-600 dark:text-red-400", bgColor: "bg-red-500/15" }
  }
  if (lower.includes("login") || lower.includes("auth") || lower.includes("sign")) {
    return { icon: LogIn, color: "text-violet-600 dark:text-violet-400", bgColor: "bg-violet-500/15" }
  }
  return { icon: Activity, color: "text-muted-foreground", bgColor: "bg-muted" }
}

function getResourceType(action: string, targetLabel?: string | null): string | null {
  const lower = action.toLowerCase()
  if (lower.includes("device")) return "Device"
  if (lower.includes("ticket") || lower.includes("support")) return "Ticket"
  if (lower.includes("extension") || lower.includes("voice")) return "Extension"
  if (lower.includes("fax")) return "Fax"
  if (lower.includes("team")) return "Team"
  if (lower.includes("user") || lower.includes("member")) return "User"
  if (lower.includes("tag")) return "Tag"
  if (lower.includes("role")) return "Role"
  if (targetLabel) {
    // Try to infer from target label if no action match
    return null
  }
  return null
}

interface RecentActivityCardProps {
  activities: ActivityLogEntry[]
  isLoading: boolean
  isAdmin?: boolean
}

export function RecentActivityCard({ activities, isLoading, isAdmin = false }: RecentActivityCardProps) {
  if (isLoading) {
    return (
      <Card>
        <CardHeader className="space-y-1 pb-4">
          <CardTitle className="text-lg">Recent Activity</CardTitle>
          <CardDescription>Latest events across the platform</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
            <div key={`activity-skeleton-${i}`} className="flex items-center gap-3">
              <Skeleton className="h-8 w-8 shrink-0 rounded-full" />
              <div className="flex-1 space-y-1">
                <Skeleton className="h-4 w-3/4" />
                <Skeleton className="h-3 w-1/2" />
              </div>
              <Skeleton className="h-3 w-12" />
            </div>
          ))}
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="space-y-1 pb-4">
        <CardTitle className="text-lg">Recent Activity</CardTitle>
        <CardDescription>Latest events across the platform</CardDescription>
      </CardHeader>
      <CardContent>
        {activities.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-muted">
              <Activity className="h-6 w-6 text-muted-foreground" />
            </div>
            <p className="text-sm font-medium text-muted-foreground">No recent activity</p>
            <p className="mt-1 text-xs text-muted-foreground/70">Activity will appear here as events occur.</p>
          </div>
        ) : (
          <div className="space-y-1">
            {activities.map((activity) => {
              const style = getActionStyle(activity.action)
              const ActionIcon = style.icon
              const resourceType = getResourceType(activity.action, activity.targetLabel)

              return (
                <div key={activity.id} className="flex items-start gap-3 rounded-lg px-3 py-2.5 transition-colors hover:bg-muted/50">
                  <div className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full ${style.bgColor}`}>
                    <ActionIcon className={`h-3.5 w-3.5 ${style.color}`} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium">{formatActionLabel(activity.action)}</p>
                      {resourceType && (
                        <Badge variant="secondary" className="h-5 px-1.5 py-0 text-[10px] font-medium">
                          {resourceType}
                        </Badge>
                      )}
                    </div>
                    <p className="truncate text-xs text-muted-foreground">
                      {activity.actorEmail ?? "System"}
                      {activity.targetLabel ? ` • ${activity.targetLabel}` : ""}
                    </p>
                  </div>
                  <span className="shrink-0 pt-0.5 text-xs text-muted-foreground">{formatRelativeTime(activity.createdAt)}</span>
                </div>
              )
            })}
          </div>
        )}
        {isAdmin && activities.length > 0 && (
          <div className="mt-4 border-t pt-3">
            <Link
              to="/admin/audit"
              className="flex items-center justify-center gap-1.5 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
            >
              View all activity
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
