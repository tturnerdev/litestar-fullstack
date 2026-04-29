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

interface RecentActivityCardProps {
  activities: ActivityLogEntry[]
  isLoading: boolean
}

export function RecentActivityCard({ activities, isLoading }: RecentActivityCardProps) {
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
              <Skeleton className="h-2 w-2 shrink-0 rounded-full" />
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
          <p className="py-4 text-center text-sm text-muted-foreground">No recent activity to show.</p>
        ) : (
          <div className="space-y-1">
            {activities.map((activity) => (
              <div key={activity.id} className="flex items-start gap-3 rounded-lg px-3 py-2.5 transition-colors hover:bg-muted/50">
                <div className="mt-2 h-2 w-2 shrink-0 rounded-full bg-primary/60" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium">{formatActionLabel(activity.action)}</p>
                  <p className="truncate text-xs text-muted-foreground">
                    {activity.actorEmail ?? "System"}
                    {activity.targetLabel ? ` • ${activity.targetLabel}` : ""}
                  </p>
                </div>
                <span className="shrink-0 text-xs text-muted-foreground">{formatRelativeTime(activity.createdAt)}</span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
