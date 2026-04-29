import { Activity, Globe, LogIn, Pencil, Plus, Shield, Trash2 } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useAdminUserAuditLogs } from "@/lib/api/hooks/admin"

const ACTION_CONFIG: Record<string, { label: string; icon: typeof Activity; variant: "default" | "secondary" | "outline" | "destructive" }> = {
  login: { label: "Logged in", icon: LogIn, variant: "default" },
  logout: { label: "Logged out", icon: LogIn, variant: "secondary" },
  create: { label: "Created", icon: Plus, variant: "default" },
  update: { label: "Updated", icon: Pencil, variant: "secondary" },
  delete: { label: "Deleted", icon: Trash2, variant: "destructive" },
  password_change: { label: "Changed password", icon: Shield, variant: "secondary" },
  mfa_enable: { label: "Enabled MFA", icon: Shield, variant: "default" },
  mfa_disable: { label: "Disabled MFA", icon: Shield, variant: "destructive" },
}

function getActionConfig(action: string) {
  const normalized = action.toLowerCase().replace(/[.\-\s]/g, "_")
  for (const [key, config] of Object.entries(ACTION_CONFIG)) {
    if (normalized.includes(key)) return config
  }
  return { label: action, icon: Activity, variant: "outline" as const }
}

function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString)
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

function TimelineSkeleton() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Activity</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          {Array.from({ length: 5 }).map((_, i) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
            <div key={`timeline-skeleton-${i}`} className="flex gap-4">
              <div className="flex flex-col items-center">
                <Skeleton className="h-3 w-3 rounded-full" />
                {i < 4 && <Skeleton className="mt-1 h-10 w-px" />}
              </div>
              <div className="flex-1 space-y-1.5 pb-2">
                <Skeleton className="h-5 w-24" />
                <Skeleton className="h-4 w-48" />
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

export function UserActivityTimeline({ userId }: { userId: string }) {
  const { data, isLoading, isError } = useAdminUserAuditLogs(userId)

  if (isLoading) {
    return <TimelineSkeleton />
  }

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Recent Activity</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground text-sm">Unable to load activity.</CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Activity</CardTitle>
      </CardHeader>
      <CardContent>
        {data.items.length === 0 ? (
          <p className="text-muted-foreground text-sm">No recent activity</p>
        ) : (
          <div className="space-y-0">
            {data.items.map((entry, index) => {
              const config = getActionConfig(entry.action)
              const Icon = config.icon
              const isLast = index === data.items.length - 1

              return (
                <div key={entry.id} className="flex gap-4">
                  {/* Timeline track */}
                  <div className="flex flex-col items-center pt-1">
                    <div className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-border bg-background">
                      <Icon className="h-3 w-3 text-muted-foreground" />
                    </div>
                    {!isLast && <div className="mt-0.5 w-px flex-1 bg-border" />}
                  </div>

                  {/* Content */}
                  <div className={`flex-1 pb-6 ${isLast ? "pb-0" : ""}`}>
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant={config.variant} className="text-xs">
                        {config.label}
                      </Badge>
                      <span className="text-xs text-muted-foreground" title={new Date(entry.createdAt).toLocaleString()}>
                        {formatRelativeTime(entry.createdAt)}
                      </span>
                    </div>

                    {(entry.targetType || entry.targetLabel) && (
                      <p className="mt-1 text-sm text-muted-foreground">
                        {entry.targetType && <span className="capitalize">{entry.targetType}</span>}
                        {entry.targetLabel && <span> &middot; {entry.targetLabel}</span>}
                      </p>
                    )}

                    {entry.ipAddress && (
                      <p className="mt-0.5 flex items-center gap-1 text-xs text-muted-foreground/70">
                        <Globe className="h-3 w-3" />
                        {entry.ipAddress}
                      </p>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
