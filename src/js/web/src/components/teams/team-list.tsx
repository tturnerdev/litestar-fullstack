import { useQuery } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { Check, ChevronRight, LayoutGrid, List, Plus, Search, Shield, Users } from "lucide-react"
import { useEffect, useMemo, useState } from "react"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { formatRelativeTimeShort } from "@/lib/date-utils"
import { useAuthStore } from "@/lib/auth"
import { listTeams, type Team } from "@/lib/generated/api"

function getTeamInitials(name: string): string {
  return name
    .split(/\s+/)
    .map((word) => word[0])
    .join("")
    .toUpperCase()
    .slice(0, 2)
}

function getTeamColor(name: string): string {
  const colors = [
    "bg-blue-500/15 text-blue-600 dark:text-blue-400",
    "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
    "bg-violet-500/15 text-violet-600 dark:text-violet-400",
    "bg-amber-500/15 text-amber-600 dark:text-amber-400",
    "bg-rose-500/15 text-rose-600 dark:text-rose-400",
    "bg-cyan-500/15 text-cyan-600 dark:text-cyan-400",
    "bg-fuchsia-500/15 text-fuchsia-600 dark:text-fuchsia-400",
    "bg-orange-500/15 text-orange-600 dark:text-orange-400",
  ]
  const index = name.split("").reduce((acc, char) => acc + char.charCodeAt(0), 0) % colors.length
  return colors[index]
}

type SortOption = "name-asc" | "name-desc" | "members-most" | "members-fewest"

export function TeamList() {
  const { user, currentTeam, setCurrentTeam, setTeams } = useAuthStore()
  const [search, setSearch] = useState("")
  const [sort, setSort] = useState<SortOption>("name-asc")
  const [viewMode, setViewMode] = useState<"grid" | "list">("grid")

  const {
    data: rawTeamsData = [],
    isLoading,
    isError,
  } = useQuery({
    queryKey: ["teams"],
    queryFn: async () => {
      const response = await listTeams()
      const data = response.data
      if (Array.isArray(data)) return data
      return data?.items ?? []
    },
  })

  const teamsData = Array.isArray(rawTeamsData) ? rawTeamsData : (rawTeamsData as any)?.items ?? []

  useEffect(() => {
    if (!isLoading && !isError) {
      setTeams(teamsData)
    }
  }, [isError, isLoading, setTeams, teamsData])

  const filteredTeams = useMemo(() => {
    const filtered = teamsData.filter(
      (team: Team) =>
        team.name.toLowerCase().includes(search.toLowerCase()) ||
        team.description?.toLowerCase().includes(search.toLowerCase()),
    )
    return [...filtered].sort((a: Team, b: Team) => {
      switch (sort) {
        case "name-asc":
          return a.name.localeCompare(b.name)
        case "name-desc":
          return b.name.localeCompare(a.name)
        case "members-most":
          return (b.members?.length ?? 0) - (a.members?.length ?? 0)
        case "members-fewest":
          return (a.members?.length ?? 0) - (b.members?.length ?? 0)
        default:
          return 0
      }
    })
  }, [teamsData, search, sort])

  if (isLoading) {
    return (
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <SkeletonCard key={i} />
        ))}
      </div>
    )
  }

  if (isError) {
    return (
      <Card className="border-dashed border-destructive/30 bg-destructive/5">
        <CardContent className="py-12 text-center">
          <p className="text-muted-foreground">We couldn't load teams yet. Try refreshing.</p>
        </CardContent>
      </Card>
    )
  }

  if (teamsData.length === 0) {
    return (
      <EmptyState
        icon={Users}
        title="Create your first team"
        description="Teams help you organize members and control access across the app. Get started by creating your first team."
        action={
          <Button asChild size="lg">
            <Link to="/teams/new">
              <Plus className="mr-2 h-4 w-4" />
              Create team
            </Link>
          </Button>
        }
      />
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          {teamsData.length > 3 && (
            <div className="relative max-w-md">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input placeholder="Search teams..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-10" />
            </div>
          )}
          <Select value={sort} onValueChange={(v) => setSort(v as SortOption)}>
            <SelectTrigger className="w-[160px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="name-asc">Name A-Z</SelectItem>
              <SelectItem value="name-desc">Name Z-A</SelectItem>
              <SelectItem value="members-most">Members (most)</SelectItem>
              <SelectItem value="members-fewest">Members (fewest)</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-center gap-3">
          <p className="text-xs text-muted-foreground">
            Showing {filteredTeams.length} of {teamsData.length} team{teamsData.length === 1 ? "" : "s"}
          </p>
          <div className="flex items-center rounded-md border">
            <Button
              variant={viewMode === "grid" ? "secondary" : "ghost"}
              size="icon"
              className="h-8 w-8 rounded-r-none"
              onClick={() => setViewMode("grid")}
              aria-label="Grid view"
            >
              <LayoutGrid className="h-4 w-4" />
            </Button>
            <Button
              variant={viewMode === "list" ? "secondary" : "ghost"}
              size="icon"
              className="h-8 w-8 rounded-l-none"
              onClick={() => setViewMode("list")}
              aria-label="List view"
            >
              <List className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </div>

      {viewMode === "grid" ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {filteredTeams.map((team: Team) => {
            const isCurrent = currentTeam?.id === team.id
            const tags = team.tags ?? []
            const memberCount = team.members?.length ?? 0
            const userMembership = team.members?.find((m) => m.userId === user?.id)
            const isOwner = userMembership?.isOwner
            const isAdmin = userMembership?.role === "ADMIN"
            const createdAt = (team as Team & { createdAt?: string }).createdAt

            return (
              <Card
                key={team.id}
                className={`group relative overflow-hidden transition-all hover:shadow-md ${
                  isCurrent ? "border-primary/50 bg-primary/5 shadow-primary/10 shadow-sm ring-1 ring-primary/20" : "border-border/60 hover:border-border"
                }`}
              >
                {/* Active indicator stripe */}
                {isCurrent && <div className="absolute inset-y-0 left-0 w-1 bg-primary" />}

                <CardHeader className="pb-3">
                  <div className="flex items-start gap-3">
                    <button type="button" onClick={() => setCurrentTeam(team)} className="group/avatar relative" title={isCurrent ? "Current team" : "Click to switch to this team"}>
                      <Avatar className={`h-12 w-12 transition-all ${getTeamColor(team.name)} ${!isCurrent && "group-hover/avatar:ring-2 group-hover/avatar:ring-primary/30"}`}>
                        <AvatarFallback className={`text-sm font-semibold ${getTeamColor(team.name)}`}>{getTeamInitials(team.name)}</AvatarFallback>
                      </Avatar>
                      {isCurrent && (
                        <div className="absolute -bottom-1 -right-1 flex h-5 w-5 items-center justify-center rounded-full bg-primary text-primary-foreground ring-2 ring-background">
                          <Check className="h-3 w-3" />
                        </div>
                      )}
                    </button>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Link to="/teams/$teamId" params={{ teamId: team.id }} className="font-semibold hover:underline truncate text-foreground">
                              {team.name}
                            </Link>
                          </TooltipTrigger>
                          <TooltipContent>{team.name}</TooltipContent>
                        </Tooltip>
                        {team.isActive === false && (
                          <Badge variant="destructive" className="h-5 px-1.5 text-[10px] font-medium">
                            Inactive
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="text-xs text-muted-foreground flex items-center gap-1">
                          <Users className="h-3 w-3" />
                          {memberCount} member{memberCount !== 1 ? "s" : ""}
                        </span>
                        {(isOwner || isAdmin) && (
                          <Badge variant="outline" className="h-5 px-1.5 text-[10px] font-medium">
                            {isOwner ? (
                              "Owner"
                            ) : (
                              <>
                                <Shield className="mr-0.5 h-2.5 w-2.5" />
                                Admin
                              </>
                            )}
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>
                </CardHeader>

                <CardContent className="pt-0">
                  {team.description ? (
                    <p className="text-sm text-muted-foreground line-clamp-2 min-h-10">{team.description}</p>
                  ) : (
                    <p className="text-sm text-muted-foreground/60 italic min-h-10">No description</p>
                  )}

                  {tags.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mt-3">
                      {tags.slice(0, 3).map((tag) => (
                        <Badge key={tag.id} variant="secondary" className="text-[10px] px-2 py-0.5">
                          {tag.name}
                        </Badge>
                      ))}
                      {tags.length > 3 && (
                        <Badge variant="outline" className="text-[10px] px-2 py-0.5">
                          +{tags.length - 3}
                        </Badge>
                      )}
                    </div>
                  )}

                  <div className="mt-4 pt-3 border-t border-border/60 flex items-center justify-between">
                    <Link
                      to="/teams/$teamId"
                      params={{ teamId: team.id }}
                      className="flex items-center gap-1 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors group/link"
                    >
                      <span>View team</span>
                      <ChevronRight className="h-4 w-4 transition-transform group-hover/link:translate-x-0.5" />
                    </Link>
                    {createdAt && (
                      <span className="text-[10px] text-muted-foreground/60">Created {formatRelativeTimeShort(createdAt)}</span>
                    )}
                  </div>
                </CardContent>
              </Card>
            )
          })}

          {/* Create Team placeholder card */}
          <Card className="group border-dashed border-2 border-border/60 hover:border-primary/40 transition-all hover:shadow-md">
            <Link to="/teams/new" className="flex h-full flex-col items-center justify-center py-12 text-muted-foreground hover:text-foreground transition-colors">
              <div className="flex h-12 w-12 items-center justify-center rounded-full border-2 border-dashed border-current mb-3">
                <Plus className="h-6 w-6" />
              </div>
              <span className="text-sm font-medium">Create Team</span>
            </Link>
          </Card>
        </div>
      ) : (
        <div className="space-y-2">
          {filteredTeams.map((team: Team) => {
            const isCurrent = currentTeam?.id === team.id
            const tags = team.tags ?? []
            const memberCount = team.members?.length ?? 0
            const userMembership = team.members?.find((m) => m.userId === user?.id)
            const isOwner = userMembership?.isOwner
            const isAdmin = userMembership?.role === "ADMIN"
            const createdAt = (team as Team & { createdAt?: string }).createdAt

            return (
              <Card
                key={team.id}
                className={`group relative overflow-hidden transition-all hover:shadow-sm ${
                  isCurrent ? "border-primary/50 bg-primary/5 ring-1 ring-primary/20" : "border-border/60 hover:border-border"
                }`}
              >
                {isCurrent && <div className="absolute inset-y-0 left-0 w-1 bg-primary" />}
                <div className="flex items-center gap-4 px-4 py-3">
                  <button type="button" onClick={() => setCurrentTeam(team)} className="group/avatar relative shrink-0" title={isCurrent ? "Current team" : "Click to switch to this team"}>
                    <Avatar className={`h-10 w-10 transition-all ${getTeamColor(team.name)} ${!isCurrent && "group-hover/avatar:ring-2 group-hover/avatar:ring-primary/30"}`}>
                      <AvatarFallback className={`text-xs font-semibold ${getTeamColor(team.name)}`}>{getTeamInitials(team.name)}</AvatarFallback>
                    </Avatar>
                    {isCurrent && (
                      <div className="absolute -bottom-0.5 -right-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-primary text-primary-foreground ring-2 ring-background">
                        <Check className="h-2.5 w-2.5" />
                      </div>
                    )}
                  </button>

                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Link to="/teams/$teamId" params={{ teamId: team.id }} className="font-semibold hover:underline truncate text-foreground text-sm">
                            {team.name}
                          </Link>
                        </TooltipTrigger>
                        <TooltipContent>{team.name}</TooltipContent>
                      </Tooltip>
                      {team.isActive === false && (
                        <Badge variant="destructive" className="h-5 px-1.5 text-[10px] font-medium">
                          Inactive
                        </Badge>
                      )}
                      {(isOwner || isAdmin) && (
                        <Badge variant="outline" className="h-5 px-1.5 text-[10px] font-medium">
                          {isOwner ? (
                            "Owner"
                          ) : (
                            <>
                              <Shield className="mr-0.5 h-2.5 w-2.5" />
                              Admin
                            </>
                          )}
                        </Badge>
                      )}
                    </div>
                    {team.description && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <p className="text-xs text-muted-foreground truncate mt-0.5">{team.description}</p>
                        </TooltipTrigger>
                        <TooltipContent>{team.description}</TooltipContent>
                      </Tooltip>
                    )}
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    {tags.length > 0 && (
                      <div className="hidden md:flex items-center gap-1">
                        {tags.slice(0, 2).map((tag) => (
                          <Badge key={tag.id} variant="secondary" className="text-[10px] px-2 py-0.5">
                            {tag.name}
                          </Badge>
                        ))}
                        {tags.length > 2 && (
                          <Badge variant="outline" className="text-[10px] px-2 py-0.5">
                            +{tags.length - 2}
                          </Badge>
                        )}
                      </div>
                    )}
                    <span className="text-xs text-muted-foreground flex items-center gap-1">
                      <Users className="h-3 w-3" />
                      {memberCount}
                    </span>
                    {createdAt && (
                      <span className="hidden sm:block text-[10px] text-muted-foreground/60">{formatRelativeTimeShort(createdAt)}</span>
                    )}
                    <Link to="/teams/$teamId" params={{ teamId: team.id }}>
                      <ChevronRight className="h-4 w-4 text-muted-foreground group-hover:text-foreground transition-colors" />
                    </Link>
                  </div>
                </div>
              </Card>
            )
          })}

          {/* Create Team row */}
          <Card className="border-dashed border-2 border-border/60 hover:border-primary/40 transition-all">
            <Link to="/teams/new" className="flex items-center gap-3 px-4 py-3 text-muted-foreground hover:text-foreground transition-colors">
              <div className="flex h-10 w-10 items-center justify-center rounded-full border-2 border-dashed border-current">
                <Plus className="h-5 w-5" />
              </div>
              <span className="text-sm font-medium">Create Team</span>
            </Link>
          </Card>
        </div>
      )}

      {filteredTeams.length === 0 && search && (
        <EmptyState
          icon={Search}
          variant="no-results"
          title="No matching teams"
          description={`No teams match "${search}". Try a different search term.`}
        />
      )}
    </div>
  )
}
