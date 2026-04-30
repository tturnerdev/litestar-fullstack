import { useQuery } from "@tanstack/react-query"
import { createFileRoute, Link, useParams } from "@tanstack/react-router"
import {
  Activity,
  ArrowLeft,
  Crown,
  Pencil,
  Settings,
  Shield,
  Users,
} from "lucide-react"
import { useEffect, useState } from "react"
import { TeamActivity } from "@/components/teams/team-activity"
import { TeamMembers } from "@/components/teams/team-members"
import { TeamSettings } from "@/components/teams/team-settings"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { CopyButton } from "@/components/ui/copy-button"
import { useAuthStore } from "@/lib/auth"
import { getTeam, type TeamMember } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/teams/$teamId/")({
  component: TeamDetail,
})

// ── Helpers ──────────────────────────────────────────────────────────────

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

// ── Main component ──────────────────────────────────────────────────────

function TeamDetail() {
  const { teamId } = useParams({ from: "/_app/teams/$teamId/" as const })
  const { user, currentTeam, setCurrentTeam } = useAuthStore()
  const [activeTab, setActiveTab] = useState("members")

  const {
    data: team,
    isLoading: isTeamLoading,
    isError: isTeamError,
  } = useQuery({
    queryKey: ["team", teamId],
    queryFn: async () => {
      const response = await getTeam({ path: { team_id: teamId } })
      return response.data
    },
  })

  useEffect(() => {
    if (team && team.id !== currentTeam?.id) {
      setCurrentTeam(team)
    }
  }, [currentTeam?.id, setCurrentTeam, team])

  if (isTeamLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Teams" title="Team Details" />
        <PageSection>
          <SkeletonCard />
        </PageSection>
      </PageContainer>
    )
  }

  if (isTeamError || !team) {
    return (
      <PageContainer className="flex-1">
        <div className="flex flex-col items-center justify-center py-20 text-center">
          <Users className="mb-3 h-10 w-10 text-muted-foreground/50" />
          <h2 className="text-lg font-semibold">{isTeamError ? "Unable to load team" : "Team not found"}</h2>
          <p className="mt-1 text-sm text-muted-foreground">{isTeamError ? "Something went wrong. Please try refreshing the page." : "This team may have been deleted or you don't have access."}</p>
          <Button variant="outline" size="sm" asChild className="mt-4">
            <Link to="/teams">
              <ArrowLeft className="mr-2 h-4 w-4" /> Back to teams
            </Link>
          </Button>
        </div>
      </PageContainer>
    )
  }

  const members = team.members ?? []
  const owner = members.find((member) => member.isOwner)
  const ownerId = owner?.userId
  const isOwner = ownerId === user?.id
  const isAdmin = members.some((member) => member.userId === user?.id && member.role === "ADMIN")
  const canManageMembers = isOwner || user?.isSuperuser || isAdmin
  const tags = team.tags ?? []

  const userMembership = members.find((m: TeamMember) => m.userId === user?.id)
  const userRole = userMembership?.isOwner ? "Owner" : userMembership?.role === "ADMIN" ? "Admin" : userMembership ? "Member" : null

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Teams"
        title={team.name}
        description={team.description || "No description provided."}
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/home">Home</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/teams">Teams</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>{team.name}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-3">
            {team.isActive === false ? (
              <Badge variant="destructive" className="text-[10px]">
                Inactive
              </Badge>
            ) : (
              <Badge className="gap-1 bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">
                Active
              </Badge>
            )}
            {userRole && (
              <Badge variant="outline" className="gap-1 text-[10px]">
                {userRole === "Owner" && <Crown className="h-2.5 w-2.5" />}
                {userRole === "Admin" && <Shield className="h-2.5 w-2.5" />}
                {userRole}
              </Badge>
            )}
            <Button variant="outline" size="sm" asChild>
              <Link to="/teams/$teamId/edit" params={{ teamId }}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
              </Link>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to="/teams">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
          </div>
        }
      />

      {/* Team Info Card */}
      <PageSection>
        <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
          <CardContent className="p-6">
            <div className="flex flex-col gap-6 sm:flex-row sm:items-center">
              <Avatar className={`h-16 w-16 ${getTeamColor(team.name)}`}>
                <AvatarFallback className={`text-xl font-bold ${getTeamColor(team.name)}`}>
                  {getTeamInitials(team.name)}
                </AvatarFallback>
              </Avatar>

              <div className="flex-1 space-y-2">
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-xl font-semibold">{team.name}</h2>
                </div>
                {team.description && <p className="text-sm text-muted-foreground">{team.description}</p>}
                {tags.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {tags.map((tag) => (
                      <Badge key={tag.id} variant="secondary" className="text-[10px] px-2 py-0.5">
                        {tag.name}
                      </Badge>
                    ))}
                  </div>
                )}
                {/* Team ID with copy */}
                <div className="flex items-center gap-1 pt-1">
                  <span className="text-xs text-muted-foreground">ID:</span>
                  <span className="font-mono text-xs text-muted-foreground">{teamId}</span>
                  <CopyButton value={teamId} label="team ID" />
                </div>
              </div>

              <div className="flex gap-6 sm:gap-8">
                <div className="text-center">
                  <p className="text-2xl font-bold text-foreground">{members.length}</p>
                  <p className="text-xs text-muted-foreground">Members</p>
                </div>
                <Separator orientation="vertical" className="hidden h-12 sm:block" />
                {owner && (
                  <div className="text-center">
                    <p className="text-sm font-medium text-foreground">{owner.name ?? owner.email}</p>
                    <p className="text-xs text-muted-foreground">Owner</p>
                  </div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Tabs Section */}
      <PageSection delay={0.1}>
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="members" className="gap-1.5">
              <Users className="h-4 w-4" />
              Members
              <Badge variant="secondary" className="ml-1 h-5 px-1.5 text-[10px]">
                {members.length}
              </Badge>
            </TabsTrigger>
            {canManageMembers && (
              <TabsTrigger value="settings" className="gap-1.5">
                <Settings className="h-4 w-4" />
                Settings
              </TabsTrigger>
            )}
            <TabsTrigger value="activity" className="gap-1.5">
              <Activity className="h-4 w-4" />
              Activity
            </TabsTrigger>
          </TabsList>

          <TabsContent value="members" className="mt-6">
            <TeamMembers
              team={team}
              teamId={teamId}
              canManageMembers={!!canManageMembers}
              isOwner={isOwner}
            />
          </TabsContent>

          {canManageMembers && (
            <TabsContent value="settings" className="mt-6">
              <TeamSettings
                team={team}
                teamId={teamId}
                isOwner={isOwner}
              />
            </TabsContent>
          )}

          <TabsContent value="activity" className="mt-6">
            <TeamActivity team={team} />
          </TabsContent>
        </Tabs>
      </PageSection>
    </PageContainer>
  )
}
