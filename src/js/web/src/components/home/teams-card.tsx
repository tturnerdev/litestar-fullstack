import { Link } from "@tanstack/react-router"
import { Users } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import type { Team } from "@/lib/generated/api"

interface TeamsCardProps {
  teams: Team[]
  isLoading: boolean
}

export function TeamsCard({ teams, isLoading }: TeamsCardProps) {
  if (isLoading) {
    return (
      <Card hover>
        <CardHeader className="space-y-1">
          <CardTitle className="text-lg">Your Teams</CardTitle>
          <CardDescription>Teams you're a member of</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
            <Skeleton key={`team-skeleton-${i}`} className="h-12 w-full rounded-lg" />
          ))}
        </CardContent>
      </Card>
    )
  }

  return (
    <Card hover>
      <CardHeader className="space-y-1">
        <CardTitle className="text-lg">Your Teams</CardTitle>
        <CardDescription>Teams you're a member of</CardDescription>
      </CardHeader>
      <CardContent>
        {teams.length > 0 ? (
          <div className="space-y-2">
            {teams.slice(0, 5).map((team) => (
              <Link
                key={team.id}
                to="/teams/$teamId"
                params={{ teamId: team.id }}
                className="flex items-center gap-3 rounded-lg border border-border/60 bg-background/60 p-3 transition-colors hover:bg-accent"
              >
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-primary/10 text-primary">
                  <Users className="h-4 w-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{team.name}</p>
                  {team.description && (
                    <p className="truncate text-xs text-muted-foreground">{team.description}</p>
                  )}
                </div>
                {team.members && (
                  <span className="shrink-0 text-xs text-muted-foreground">
                    {team.members.length} {team.members.length === 1 ? "member" : "members"}
                  </span>
                )}
              </Link>
            ))}
            {teams.length > 5 && (
              <Link to="/teams" className="block pt-1 text-center text-sm text-muted-foreground hover:text-foreground">
                View all {teams.length} teams
              </Link>
            )}
          </div>
        ) : (
          <div className="py-6 text-center">
            <p className="mb-3 text-sm text-muted-foreground">You're not a member of any teams yet.</p>
            <Button asChild size="sm" variant="outline">
              <Link to="/teams/new">Create your first team</Link>
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
