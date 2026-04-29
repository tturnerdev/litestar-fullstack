import { Link } from "@tanstack/react-router"
import { ArrowRight, LogIn, Pencil, Plus, Trash2 } from "lucide-react"
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useAdminRecentActivity } from "@/lib/api/hooks/admin"

function getActionStyle(action: string) {
  const lower = action.toLowerCase()
  if (lower.includes("delete") || lower.includes("remove")) {
    return {
      icon: Trash2,
      dotColor: "bg-red-500",
      iconColor: "text-red-600 dark:text-red-400",
      bgColor: "bg-red-500/10",
    }
  }
  if (lower.includes("update") || lower.includes("edit") || lower.includes("change")) {
    return {
      icon: Pencil,
      dotColor: "bg-blue-500",
      iconColor: "text-blue-600 dark:text-blue-400",
      bgColor: "bg-blue-500/10",
    }
  }
  if (lower.includes("login") || lower.includes("sign") || lower.includes("auth")) {
    return {
      icon: LogIn,
      dotColor: "bg-amber-500",
      iconColor: "text-amber-600 dark:text-amber-400",
      bgColor: "bg-amber-500/10",
    }
  }
  // Default: create / other
  return {
    icon: Plus,
    dotColor: "bg-emerald-500",
    iconColor: "text-emerald-600 dark:text-emerald-400",
    bgColor: "bg-emerald-500/10",
  }
}

function formatRelativeTime(dateString: string): string {
  const now = Date.now()
  const date = new Date(dateString).getTime()
  const diffSeconds = Math.floor((now - date) / 1000)

  if (diffSeconds < 60) return "just now"
  const diffMinutes = Math.floor(diffSeconds / 60)
  if (diffMinutes < 60) return `${diffMinutes}m ago`
  const diffHours = Math.floor(diffMinutes / 60)
  if (diffHours < 24) return `${diffHours}h ago`
  const diffDays = Math.floor(diffHours / 24)
  if (diffDays < 7) return `${diffDays}d ago`
  return new Date(dateString).toLocaleDateString()
}

function TimelineSkeleton() {
  return (
    <Card>
      <CardHeader>
        <Skeleton className="h-5 w-32" />
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          {Array.from({ length: 5 }).map((_, i) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
            <div key={`timeline-skeleton-${i}`} className="flex gap-4">
              <div className="flex flex-col items-center">
                <Skeleton className="h-8 w-8 rounded-full" />
                {i < 4 && <Skeleton className="mt-2 h-10 w-0.5" />}
              </div>
              <div className="flex-1 space-y-2 pb-2">
                <Skeleton className="h-4 w-3/4" />
                <Skeleton className="h-3 w-1/2" />
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

export function RecentActivity() {
  const { data, isLoading, isError } = useAdminRecentActivity()

  if (isLoading) {
    return <TimelineSkeleton />
  }

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Recent Activity</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">We could not load recent activity.</CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Activity</CardTitle>
      </CardHeader>
      <CardContent>
        {data.activities.length === 0 ? (
          <p className="text-muted-foreground text-sm">No recent activity yet.</p>
        ) : (
          <div className="relative">
            {data.activities.map((activity, index) => {
              const style = getActionStyle(activity.action)
              const Icon = style.icon
              const isLast = index === data.activities.length - 1

              return (
                <div key={activity.id} className="group relative flex gap-4">
                  {/* Timeline line */}
                  <div className="flex flex-col items-center">
                    <div
                      className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${style.bgColor} ${style.iconColor} transition-colors`}
                    >
                      <Icon className="h-3.5 w-3.5" />
                    </div>
                    {!isLast && <div className="mt-1 h-full w-px bg-border" />}
                  </div>

                  {/* Content */}
                  <div className={`flex-1 ${isLast ? "pb-0" : "pb-6"}`}>
                    <div className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1">
                      <p className="text-sm font-medium leading-tight">{activity.action}</p>
                      <span className="shrink-0 text-xs text-muted-foreground">{formatRelativeTime(activity.createdAt)}</span>
                    </div>
                    <p className="mt-0.5 text-xs text-muted-foreground">
                      {activity.actorEmail ?? "System"}
                      {activity.targetLabel ? ` · ${activity.targetLabel}` : ""}
                    </p>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </CardContent>
      <CardFooter className="border-t pt-4">
        <Link to="/admin/audit" className="group inline-flex items-center gap-1.5 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground">
          View all activity
          <ArrowRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" />
        </Link>
      </CardFooter>
    </Card>
  )
}
