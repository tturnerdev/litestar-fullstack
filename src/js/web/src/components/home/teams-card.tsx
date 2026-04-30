import { Link } from "@tanstack/react-router"
import { motion } from "framer-motion"
import { Check, Users } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useAuthStore } from "@/lib/auth"
import type { Team } from "@/lib/generated/api"

const teamColors = [
  "bg-blue-500/15 text-blue-600 dark:text-blue-400",
  "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  "bg-violet-500/15 text-violet-600 dark:text-violet-400",
  "bg-amber-500/15 text-amber-600 dark:text-amber-400",
  "bg-rose-500/15 text-rose-600 dark:text-rose-400",
  "bg-cyan-500/15 text-cyan-600 dark:text-cyan-400",
  "bg-fuchsia-500/15 text-fuchsia-600 dark:text-fuchsia-400",
  "bg-orange-500/15 text-orange-600 dark:text-orange-400",
]

function getTeamColor(identifier: string): string {
  const index = identifier.split("").reduce((acc, char) => acc + char.charCodeAt(0), 0) % teamColors.length
  return teamColors[index]
}

function getTeamInitials(name: string): string {
  return name
    .split(/\s+/)
    .map((word) => word[0])
    .join("")
    .toUpperCase()
    .slice(0, 2)
}

interface TeamsCardProps {
  teams: Team[]
  isLoading: boolean
}

export function TeamsCard({ teams, isLoading }: TeamsCardProps) {
  const currentTeam = useAuthStore((state) => state.currentTeam)

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
            {teams.slice(0, 5).map((team, index) => {
              const isActive = currentTeam?.id === team.id
              const color = getTeamColor(team.id ?? team.name)
              const initials = getTeamInitials(team.name)
              const memberCount = team.members?.length

              return (
                <motion.div
                  key={team.id}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.25, delay: index * 0.05, ease: "easeOut" }}
                >
                  <Link
                    to="/teams/$teamId"
                    params={{ teamId: team.id }}
                    className={`group flex items-center gap-3 rounded-lg border p-3 transition-all duration-200 hover:scale-[1.01] hover:shadow-sm ${
                      isActive
                        ? "border-primary/50 bg-primary/5"
                        : "border-border/60 bg-background/60 hover:bg-accent"
                    }`}
                  >
                    <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-md ${color}`}>
                      <span className="text-xs font-semibold">{initials}</span>
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <p className="truncate text-sm font-medium">{team.name}</p>
                        {isActive && (
                          <div className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-primary">
                            <Check className="h-2.5 w-2.5 text-primary-foreground" />
                          </div>
                        )}
                      </div>
                      {team.description && (
                        <p className="truncate text-xs text-muted-foreground">{team.description}</p>
                      )}
                    </div>
                    {memberCount != null && (
                      <span className="flex shrink-0 items-center gap-1 text-xs text-muted-foreground">
                        <Users className="h-3 w-3" />
                        {memberCount}
                      </span>
                    )}
                  </Link>
                </motion.div>
              )
            })}
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
