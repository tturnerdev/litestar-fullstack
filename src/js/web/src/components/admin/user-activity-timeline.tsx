import { Activity, AlertCircle, ChevronDown, Globe, LogIn, Pencil, Plus, Shield, Trash2 } from "lucide-react"
import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { Skeleton } from "@/components/ui/skeleton"
import { useAdminUserAuditLogs } from "@/lib/api/hooks/admin"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"

type FilterType = "all" | "logins" | "changes" | "security"

const FILTER_PILLS: { key: FilterType; label: string }[] = [
  { key: "all", label: "All" },
  { key: "logins", label: "Logins" },
  { key: "changes", label: "Changes" },
  { key: "security", label: "Security" },
]

const LOGIN_ACTIONS = new Set(["login", "logout"])
const SECURITY_ACTIONS = new Set(["password_change", "mfa_enable", "mfa_disable"])
const CHANGE_ACTIONS = new Set(["create", "update", "delete"])

function matchesFilter(action: string, filter: FilterType): boolean {
  if (filter === "all") return true
  const normalized = action.toLowerCase().replace(/[.\-\s]/g, "_")
  if (filter === "logins") return [...LOGIN_ACTIONS].some((a) => normalized.includes(a))
  if (filter === "security") return [...SECURITY_ACTIONS].some((a) => normalized.includes(a))
  if (filter === "changes") return [...CHANGE_ACTIONS].some((a) => normalized.includes(a))
  return false
}

function getDotColor(action: string): string {
  const normalized = action.toLowerCase().replace(/[.\-\s]/g, "_")
  if (normalized.includes("delete")) return "bg-red-500"
  if (normalized.includes("create") || normalized.includes("login")) return "bg-green-500"
  if (normalized.includes("update")) return "bg-blue-500"
  if (normalized.includes("password") || normalized.includes("mfa")) return "bg-amber-500"
  return "bg-muted-foreground"
}

const INITIAL_DISPLAY = 10

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
  const { data, isLoading, isError, refetch } = useAdminUserAuditLogs(userId)
  const [filter, setFilter] = useState<FilterType>("all")
  const [showAll, setShowAll] = useState(false)
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set())

  if (isLoading) {
    return <TimelineSkeleton />
  }

  if (isError || !data) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load activity"
        description="Something went wrong while fetching the audit trail."
        action={
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            Try again
          </Button>
        }
      />
    )
  }

  const filtered = data.items.filter((entry) => matchesFilter(entry.action, filter))
  const displayed = showAll ? filtered : filtered.slice(0, INITIAL_DISPLAY)
  const hasMore = filtered.length > INITIAL_DISPLAY

  function toggleExpanded(id: string) {
    setExpandedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Activity</CardTitle>
      </CardHeader>
      <CardContent>
        {/* Filter pills */}
        <div className="mb-4 flex flex-wrap gap-1.5">
          {FILTER_PILLS.map((pill) => (
            <button
              key={pill.key}
              type="button"
              onClick={() => {
                setFilter(pill.key)
                setShowAll(false)
              }}
              className={`rounded-full px-3 py-1 text-xs font-medium transition-colors ${
                filter === pill.key ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground hover:bg-muted/80"
              }`}
            >
              {pill.label}
            </button>
          ))}
        </div>

        {filtered.length === 0 ? (
          <EmptyState
            icon={Activity}
            title={filter === "all" ? "No recent activity" : `No ${filter} activity`}
            description={filter === "all" ? "This user has no recorded activity yet." : "Try selecting a different filter to see activity."}
            variant="no-results"
          />
        ) : (
          <div className="space-y-0">
            {displayed.map((entry, index) => {
              const config = getActionConfig(entry.action)
              const Icon = config.icon
              const isLast = index === displayed.length - 1
              const dotColor = getDotColor(entry.action)
              const hasDetails = entry.details && Object.keys(entry.details).length > 0
              const isExpanded = expandedIds.has(entry.id)

              return (
                <div key={entry.id} className="flex gap-4 hover:bg-muted/30 rounded-lg p-2 -m-2 transition-colors">
                  {/* Timeline track */}
                  <div className="flex flex-col items-center pt-1">
                    <div className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-border bg-background`}>
                      <div className={`h-2.5 w-2.5 rounded-full ${dotColor}`} />
                    </div>
                    {!isLast && <div className="mt-0.5 w-px flex-1 bg-border" />}
                  </div>

                  {/* Content */}
                  <div className={`flex-1 pb-6 ${isLast ? "pb-0" : ""}`}>
                    <div className="flex flex-wrap items-center gap-2">
                      <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                      <Badge variant={config.variant} className="text-xs">
                        {config.label}
                      </Badge>
                      <span className="text-xs text-muted-foreground" title={formatDateTime(entry.createdAt)}>
                        {formatRelativeTimeShort(entry.createdAt)}
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

                    {hasDetails && (
                      <button
                        type="button"
                        onClick={() => toggleExpanded(entry.id)}
                        className="mt-1 flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
                      >
                        <ChevronDown className={`h-3 w-3 transition-transform ${isExpanded ? "rotate-180" : ""}`} />
                        {isExpanded ? "Hide details" : "Show details"}
                      </button>
                    )}
                    {hasDetails && isExpanded && (
                      <pre className="mt-2 rounded-md bg-muted p-3 text-xs overflow-x-auto max-h-48 overflow-y-auto">{JSON.stringify(entry.details, null, 2)}</pre>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}

        {hasMore && !showAll && (
          <div className="mt-4 flex justify-center">
            <Button variant="outline" size="sm" onClick={() => setShowAll(true)}>
              Show more ({filtered.length - INITIAL_DISPLAY} remaining)
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
