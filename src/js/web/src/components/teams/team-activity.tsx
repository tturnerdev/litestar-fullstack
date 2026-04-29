import { Activity, Shield, UserPlus } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import type { Team, TeamMember } from "@/lib/generated/api"

interface TeamActivityProps {
  team: Team
}

/**
 * Placeholder activity feed for the team detail page.
 *
 * This currently renders a static summary derived from the team's member list
 * (who joined, ownership, etc.) and a placeholder for a future audit-log or
 * event-sourced activity feed. When a team-scoped audit log API becomes
 * available, replace the placeholder items with real data.
 */
export function TeamActivity({ team }: TeamActivityProps) {
  const members = team.members ?? []
  const owner = members.find((m) => m.isOwner)

  // Derive a lightweight "recent" list from current membership state.
  // This is intentionally static -- real events would come from an audit log.
  const derivedItems: Array<{
    id: string
    icon: typeof Activity
    iconColor: string
    title: string
    description: string
  }> = []

  if (owner) {
    derivedItems.push({
      id: "owner",
      icon: Shield,
      iconColor: "text-amber-500",
      title: `${owner.name ?? owner.email} owns this team`,
      description: "Team owner has full management permissions",
    })
  }

  if (members.length > 0) {
    const admins = members.filter((m) => m.role === "ADMIN" && !m.isOwner)
    if (admins.length > 0) {
      derivedItems.push({
        id: "admins",
        icon: Shield,
        iconColor: "text-blue-500",
        title: `${admins.length} admin${admins.length !== 1 ? "s" : ""} assigned`,
        description: admins.map((a: TeamMember) => a.name ?? a.email).join(", "),
      })
    }

    derivedItems.push({
      id: "members",
      icon: UserPlus,
      iconColor: "text-emerald-500",
      title: `${members.length} total member${members.length !== 1 ? "s" : ""}`,
      description: "Current team membership count",
    })
  }

  return (
    <div className="space-y-6">
      <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-muted-foreground" />
            Recent activity
          </CardTitle>
          <CardDescription>A summary of team membership and roles. A full activity log will be available in a future release.</CardDescription>
        </CardHeader>
        <CardContent>
          {derivedItems.length > 0 ? (
            <div className="space-y-1">
              {derivedItems.map((item, index) => (
                <div key={item.id} className="flex items-start gap-3 rounded-lg p-3 transition-colors hover:bg-muted/30">
                  <div className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted ${item.iconColor}`}>
                    <item.icon className="h-4 w-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-foreground">{item.title}</p>
                    <p className="text-xs text-muted-foreground">{item.description}</p>
                  </div>
                  {index === 0 && (
                    <span className="shrink-0 rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-medium text-primary">Current</span>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="py-8 text-center text-sm text-muted-foreground">No activity recorded yet.</div>
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
