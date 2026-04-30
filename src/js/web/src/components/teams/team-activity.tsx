import { useState } from "react"
import { Activity, Mail, Pencil, ShieldCheck, UserMinus, UserPlus } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton, SkeletonAvatar } from "@/components/ui/skeleton"
import { formatRelativeTimeShort } from "@/lib/date-utils"
import type { Team, TeamMember } from "@/lib/generated/api"

// ---------------------------------------------------------------------------
// Action type -> icon & color mapping
// ---------------------------------------------------------------------------

type ActionType = "member_joined" | "member_left" | "member_role_changed" | "team_updated" | "invitation_sent"

const ACTION_CONFIG: Record<
  ActionType,
  { icon: typeof Activity; color: string; bg: string }
> = {
  member_joined: { icon: UserPlus, color: "text-emerald-500", bg: "bg-emerald-500/10" },
  member_left: { icon: UserMinus, color: "text-red-500", bg: "bg-red-500/10" },
  member_role_changed: { icon: ShieldCheck, color: "text-violet-500", bg: "bg-violet-500/10" },
  team_updated: { icon: Pencil, color: "text-sky-500", bg: "bg-sky-500/10" },
  invitation_sent: { icon: Mail, color: "text-amber-500", bg: "bg-amber-500/10" },
}

function getActionConfig(action: string) {
  return ACTION_CONFIG[action as ActionType] ?? { icon: Activity, color: "text-muted-foreground", bg: "bg-muted" }
}

// ---------------------------------------------------------------------------
// Loading skeleton
// ---------------------------------------------------------------------------

function ActivitySkeleton() {
  return (
    <div className="space-y-1">
      {Array.from({ length: 4 }).map((_, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton rows
        <div key={`activity-skeleton-${i}`} className="flex items-start gap-3 p-3">
          <SkeletonAvatar className="h-8 w-8" />
          <div className="flex-1 space-y-1.5">
            <Skeleton className="h-4 w-3/5" />
            <Skeleton className="h-3 w-2/5" />
          </div>
        </div>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/** Number of derived items to show per "page". */
const PAGE_SIZE = 5

interface TeamActivityProps {
  team: Team
  isLoading?: boolean
}

/**
 * Activity feed for the team detail page.
 *
 * Renders a summary derived from the team's current membership state (ownership,
 * admin assignments, member count) with per-action icons, relative timestamps,
 * loading skeletons, and pagination. When a team-scoped audit log API becomes
 * available, replace the derived items with real event data.
 */
export function TeamActivity({ team, isLoading = false }: TeamActivityProps) {
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE)

  const members = team.members ?? []
  const owner = members.find((m) => m.isOwner)

  // Derive a lightweight activity list from current membership state.
  const derivedItems: Array<{
    id: string
    action: string
    title: string
    description: string
    timestamp: string | null
  }> = []

  if (owner) {
    derivedItems.push({
      id: "owner",
      action: "member_role_changed",
      title: `${owner.name ?? owner.email} owns this team`,
      description: "Team owner has full management permissions",
      timestamp: null,
    })
  }

  if (members.length > 0) {
    const admins = members.filter((m) => m.role === "ADMIN" && !m.isOwner)
    if (admins.length > 0) {
      derivedItems.push({
        id: "admins",
        action: "member_role_changed",
        title: `${admins.length} admin${admins.length !== 1 ? "s" : ""} assigned`,
        description: admins.map((a: TeamMember) => a.name ?? a.email).join(", "),
        timestamp: null,
      })
    }

    // Individual member entries with join action
    for (const member of members) {
      if (member.isOwner) continue // owner already listed
      derivedItems.push({
        id: `member-${member.id}`,
        action: "member_joined",
        title: `${member.name ?? member.email} joined the team`,
        description: `Role: ${member.role ?? "MEMBER"}`,
        timestamp: null,
      })
    }

    derivedItems.push({
      id: "total-members",
      action: "team_updated",
      title: `${members.length} total member${members.length !== 1 ? "s" : ""}`,
      description: "Current team membership count",
      timestamp: null,
    })
  }

  const visibleItems = derivedItems.slice(0, visibleCount)
  const hasMore = visibleCount < derivedItems.length

  return (
    <div className="space-y-6">
      <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-muted-foreground" />
            Recent activity
          </CardTitle>
          <CardDescription>
            A summary of team membership and roles. A full activity log will be available in a future release.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <ActivitySkeleton />
          ) : derivedItems.length > 0 ? (
            <>
              <div className="space-y-1">
                {visibleItems.map((item, index) => {
                  const config = getActionConfig(item.action)
                  const Icon = config.icon
                  return (
                    <div key={item.id} className="flex items-start gap-3 rounded-lg p-3 transition-colors hover:bg-muted/30">
                      <div className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${config.bg} ${config.color}`}>
                        <Icon className="h-4 w-4" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium text-foreground">{item.title}</p>
                        <p className="text-xs text-muted-foreground">{item.description}</p>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        {item.timestamp && (
                          <span className="text-[11px] text-muted-foreground">{formatRelativeTimeShort(item.timestamp)}</span>
                        )}
                        {index === 0 && (
                          <span className="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-medium text-primary">
                            Current
                          </span>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>

              {hasMore && (
                <div className="mt-4 flex justify-center">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-xs text-muted-foreground hover:text-foreground"
                    onClick={() => setVisibleCount((c) => c + PAGE_SIZE)}
                  >
                    Load more ({derivedItems.length - visibleCount} remaining)
                  </Button>
                </div>
              )}
            </>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-muted">
                <Activity className="h-6 w-6 text-muted-foreground" />
              </div>
              <p className="text-sm font-medium text-foreground">No recent activity</p>
              <p className="mt-1 text-xs text-muted-foreground">
                Activity will appear here as team membership changes.
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Future audit log placeholder */}
      <Card className="border-dashed border-border/40 bg-muted/20">
        <CardContent className="py-10 text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-muted">
            <Activity className="h-6 w-6 text-muted-foreground" />
          </div>
          <h3 className="text-sm font-semibold text-foreground">Full activity log coming soon</h3>
          <p className="mx-auto mt-1 max-w-sm text-xs text-muted-foreground">
            Track member joins, departures, role changes, and setting updates. This feature will be available once the team audit log API is ready.
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
