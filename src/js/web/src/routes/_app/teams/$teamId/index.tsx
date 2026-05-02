import { useQuery } from "@tanstack/react-query"
import { createFileRoute, Link, useBlocker, useParams } from "@tanstack/react-router"
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Calendar,
  Clock,
  Copy,
  Crown,
  HardDrive,
  Loader2,
  MoreHorizontal,
  Pencil,
  Phone,
  Save,
  Settings,
  Shield,
  Trash2,
  Users,
  X,
} from "lucide-react"
import { useCallback, useEffect, useMemo, useState } from "react"
import { toast } from "sonner"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { TeamMembers } from "@/components/teams/team-members"
import { TeamSettings } from "@/components/teams/team-settings"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { CopyButton } from "@/components/ui/copy-button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useDevicesByTeam } from "@/lib/api/hooks/devices"
import { useDeleteTeam, useUpdateTeam } from "@/lib/api/hooks/teams"
import { useExtensionsByTeam } from "@/lib/api/hooks/voice"
import { useAuthStore } from "@/lib/auth"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { getTeam, type TeamMember } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/teams/$teamId/")({
  component: TeamDetail,
  validateSearch: (search: Record<string, unknown>): { tab?: string } => ({
    tab: (search.tab as string) || undefined,
  }),
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
  const { tab = "members" } = Route.useSearch()
  const navigate = Route.useNavigate()

  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [editing, setEditing] = useState(false)
  const [editName, setEditName] = useState("")
  const [editDescription, setEditDescription] = useState("")
  const [editTags, setEditTags] = useState("")

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

  const deleteTeamMutation = useDeleteTeam()
  const updateTeamMutation = useUpdateTeam(teamId)

  useDocumentTitle(team?.name ?? "Team Details")

  useEffect(() => {
    if (team && team.id !== currentTeam?.id) {
      setCurrentTeam(team)
    }
  }, [currentTeam?.id, setCurrentTeam, team])

  // Sync edit fields from current data
  const syncEditFields = useCallback(() => {
    if (team) {
      setEditName(team.name)
      setEditDescription(team.description ?? "")
      const tagNames = (team.tags ?? []).map((t: { name: string }) => t.name).join(", ")
      setEditTags(tagNames)
    }
  }, [team])

  useEffect(() => {
    syncEditFields()
  }, [syncEditFields])

  // Dirty check
  const formDirty = useMemo(() => {
    if (!editing || !team) return false
    const originalTags = (team.tags ?? []).map((t: { name: string }) => t.name).join(", ")
    return editName !== team.name || editDescription !== (team.description ?? "") || editTags !== originalTags
  }, [editing, team, editName, editDescription, editTags])

  // Block navigation when dirty
  const blocker = useBlocker({
    shouldBlockFn: () => formDirty,
    withResolver: true,
  })

  function handleStartEditing() {
    syncEditFields()
    setEditing(true)
  }

  function handleCancelEditing() {
    syncEditFields()
    setEditing(false)
  }

  function handleSaveEditing() {
    if (!team) return
    const trimmedName = editName.trim()
    if (!trimmedName) return

    const payload: { name?: string | null; description?: string | null; tags?: string[] | null } = {}

    if (trimmedName !== team.name) payload.name = trimmedName
    if (editDescription !== (team.description ?? "")) {
      payload.description = editDescription || null
    }
    const originalTags = (team.tags ?? []).map((t: { name: string }) => t.name).join(", ")
    if (editTags !== originalTags) {
      const parsed = editTags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean)
      payload.tags = parsed.length > 0 ? parsed : null
    }

    if (Object.keys(payload).length === 0) {
      setEditing(false)
      return
    }

    updateTeamMutation.mutate(payload, {
      onSuccess: () => {
        toast.success("Team updated successfully")
        setEditing(false)
      },
    })
  }

  if (isTeamLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        {/* Header skeleton */}
        <div className="space-y-2">
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-4 w-64" />
        </div>
        {/* Team info card skeleton */}
        <PageSection>
          <div className="rounded-xl border border-border/60 bg-card/80 p-6 shadow-md shadow-primary/10">
            <div className="flex flex-col gap-6 sm:flex-row sm:items-center">
              <Skeleton className="h-16 w-16 rounded-full" />
              <div className="flex-1 space-y-2">
                <Skeleton className="h-6 w-40" />
                <Skeleton className="h-4 w-56" />
                <div className="flex gap-1.5">
                  <Skeleton className="h-5 w-14 rounded-full" />
                  <Skeleton className="h-5 w-16 rounded-full" />
                </div>
              </div>
              <div className="flex gap-6 sm:gap-8">
                <div className="text-center space-y-1">
                  <Skeleton className="h-8 w-10 mx-auto" />
                  <Skeleton className="h-3 w-16" />
                </div>
                <Separator orientation="vertical" className="hidden h-12 sm:block" />
                <div className="text-center space-y-1">
                  <Skeleton className="h-5 w-24" />
                  <Skeleton className="h-3 w-12 mx-auto" />
                </div>
              </div>
            </div>
          </div>
        </PageSection>
        {/* Tabs skeleton */}
        <PageSection delay={0.1}>
          <Skeleton className="h-10 w-64 rounded-lg" />
          <div className="mt-6 space-y-3">
            {Array.from({ length: 4 }).map((_, i) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
              <div key={i} className="flex items-center gap-4 rounded-lg border border-border/60 p-4">
                <Skeleton className="h-10 w-10 rounded-full" />
                <div className="flex-1 space-y-1.5">
                  <Skeleton className="h-4 w-32" />
                  <Skeleton className="h-3 w-44" />
                </div>
                <Skeleton className="h-5 w-16 rounded-full" />
              </div>
            ))}
          </div>
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
          <p className="mt-1 text-sm text-muted-foreground">
            {isTeamError ? "Something went wrong. Please try refreshing the page." : "This team may have been deleted or you don't have access."}
          </p>
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

  // biome-ignore lint/correctness/useHookAtTopLevel: hook order is correct at call site
  const { data: teamDevices, isLoading: devicesLoading } = useDevicesByTeam(teamId)
  // biome-ignore lint/correctness/useHookAtTopLevel: hook order is correct at call site
  const memberUserIds = useMemo(() => members.map((m) => m.userId), [members])
  // biome-ignore lint/correctness/useHookAtTopLevel: hook order is correct at call site
  const { data: teamExtensions, isLoading: extensionsLoading } = useExtensionsByTeam(memberUserIds)

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
              <Badge className="gap-1 bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">Active</Badge>
            )}
            {userRole && (
              <Badge
                variant={userRole === "Member" ? "outline" : undefined}
                className={
                  userRole === "Owner"
                    ? "gap-1 bg-amber-500/15 text-amber-700 hover:bg-amber-500/20 dark:text-amber-400 text-[10px]"
                    : userRole === "Admin"
                      ? "gap-1 border border-purple-500/30 bg-purple-500/10 text-purple-700 hover:bg-purple-500/15 dark:text-purple-400 text-[10px]"
                      : "gap-1 text-[10px]"
                }
              >
                {userRole === "Owner" && <Crown className="h-2.5 w-2.5" />}
                {userRole === "Admin" && <Shield className="h-2.5 w-2.5" />}
                {userRole}
              </Badge>
            )}
            {editing ? (
              <>
                <Button variant="outline" size="sm" onClick={handleCancelEditing} disabled={updateTeamMutation.isPending}>
                  <X className="mr-2 h-4 w-4" /> Cancel
                </Button>
                <Button size="sm" onClick={handleSaveEditing} disabled={updateTeamMutation.isPending || !editName.trim()}>
                  {updateTeamMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
                  {updateTeamMutation.isPending ? "Saving..." : "Save"}
                </Button>
              </>
            ) : (
              <Button variant="outline" size="sm" onClick={handleStartEditing}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
              </Button>
            )}
            <Button variant="outline" size="sm" asChild>
              <Link to="/teams">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <MoreHorizontal className="h-4 w-4" />
                  <span className="sr-only">Actions</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => navigator.clipboard.writeText(team.id)}>
                  <Copy className="mr-2 h-4 w-4" />
                  Copy Team ID
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem className="text-destructive focus:text-destructive" onClick={() => setShowDeleteDialog(true)}>
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete Team
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        }
      />

      {/* Team Info Card */}
      <PageSection>
        <SectionErrorBoundary name="Team Info">
          <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
            <CardContent className="p-6">
              {editing && formDirty && (
                <div className="mb-4 flex items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-700 dark:text-amber-400">
                  <span className="inline-block h-1.5 w-1.5 rounded-full bg-amber-500" />
                  You have unsaved changes
                </div>
              )}
              <div className="flex flex-col gap-6 sm:flex-row sm:items-start">
                <Avatar className={`h-16 w-16 ${getTeamColor(editing ? editName || team.name : team.name)}`}>
                  <AvatarFallback className={`text-xl font-bold ${getTeamColor(editing ? editName || team.name : team.name)}`}>
                    {getTeamInitials(editing ? editName || team.name : team.name)}
                  </AvatarFallback>
                </Avatar>

                <div className="flex-1 space-y-3">
                  {editing ? (
                    <>
                      <div className="space-y-2">
                        <Label htmlFor="edit-team-name">Name</Label>
                        <Input
                          id="edit-team-name"
                          value={editName}
                          onChange={(e) => setEditName(e.target.value)}
                          placeholder="Team name"
                          disabled={updateTeamMutation.isPending}
                          maxLength={100}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="edit-team-description">Description</Label>
                        <Textarea
                          id="edit-team-description"
                          value={editDescription}
                          onChange={(e) => setEditDescription(e.target.value)}
                          placeholder="Optional description"
                          disabled={updateTeamMutation.isPending}
                          maxLength={500}
                          rows={3}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="edit-team-tags">Tags</Label>
                        <Input
                          id="edit-team-tags"
                          value={editTags}
                          onChange={(e) => setEditTags(e.target.value)}
                          placeholder="e.g., engineering, backend, platform"
                          disabled={updateTeamMutation.isPending}
                        />
                        <p className="text-xs text-muted-foreground">Comma-separated list of tags.</p>
                      </div>
                    </>
                  ) : (
                    <>
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
                    </>
                  )}
                  {/* Team ID with copy */}
                  <div className="flex items-center gap-1 pt-1">
                    <span className="text-xs text-muted-foreground">ID:</span>
                    <span className="font-mono text-xs text-muted-foreground">{teamId}</span>
                    <CopyButton value={teamId} label="team ID" />
                  </div>
                  {/* Timestamps */}
                  <div className="flex items-center gap-4 pt-1">
                    {team.createdAt && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="flex items-center gap-1 text-xs text-muted-foreground cursor-default">
                            <Calendar className="h-3 w-3" />
                            Created {formatRelativeTimeShort(team.createdAt)}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>{formatDateTime(team.createdAt)}</TooltipContent>
                      </Tooltip>
                    )}
                    {team.updatedAt && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="flex items-center gap-1 text-xs text-muted-foreground cursor-default">
                            <Clock className="h-3 w-3" />
                            Updated {formatRelativeTimeShort(team.updatedAt)}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>{formatDateTime(team.updatedAt)}</TooltipContent>
                      </Tooltip>
                    )}
                  </div>
                </div>

                <div className="flex gap-6 sm:gap-8">
                  <div className="text-center">
                    <p className="text-2xl font-bold text-foreground">{members.length}</p>
                    <p className="text-xs text-muted-foreground">Members</p>
                  </div>
                  <Separator orientation="vertical" className="hidden h-12 sm:block" />
                  {owner && (
                    <div className="flex items-center gap-2.5">
                      <div className="flex h-8 w-8 items-center justify-center rounded-full bg-amber-500/15 text-sm font-medium text-amber-700 dark:text-amber-400">
                        {owner.name?.charAt(0)?.toUpperCase() ?? owner.email.charAt(0).toUpperCase()}
                      </div>
                      <div className="text-left">
                        <p className="text-sm font-medium text-foreground">{owner.name ?? owner.email}</p>
                        <div className="flex items-center gap-1.5">
                          <Badge className="h-4 gap-0.5 bg-amber-500/15 px-1.5 text-[10px] text-amber-700 hover:bg-amber-500/20 dark:text-amber-400">
                            <Crown className="h-2.5 w-2.5" />
                            Owner
                          </Badge>
                          {owner.name && <span className="text-xs text-muted-foreground">{owner.email}</span>}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Tabs Section */}
      <PageSection delay={0.1}>
        <SectionErrorBoundary name="Team Tabs">
          <Tabs value={tab} onValueChange={(value) => navigate({ search: () => ({ tab: value }), replace: true })}>
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
              <TeamMembers team={team} teamId={teamId} canManageMembers={!!canManageMembers} isOwner={isOwner} />
            </TabsContent>

            {canManageMembers && (
              <TabsContent value="settings" className="mt-6">
                <TeamSettings team={team} teamId={teamId} isOwner={isOwner} />
              </TabsContent>
            )}

            <TabsContent value="activity" className="mt-6">
              <EntityActivityPanel targetType="team" targetId={teamId} enabled={tab === "activity"} />
            </TabsContent>
          </Tabs>
        </SectionErrorBoundary>
      </PageSection>

      {/* Team Devices */}
      <PageSection delay={0.2}>
        <SectionErrorBoundary name="Team Devices">
          <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
            <CardHeader className="flex flex-row items-center justify-between">
              <div className="flex items-center gap-2">
                <CardTitle className="flex items-center gap-2">
                  <HardDrive className="h-5 w-5 text-muted-foreground" />
                  Team Devices
                </CardTitle>
                {!devicesLoading && teamDevices && teamDevices.length > 0 && (
                  <Badge variant="secondary" className="ml-1">
                    {teamDevices.length}
                  </Badge>
                )}
              </div>
            </CardHeader>
            <CardContent>
              {devicesLoading ? (
                <div className="space-y-3">
                  {Array.from({ length: 3 }).map((_, i) => (
                    // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
                    <Skeleton key={i} className="h-10 w-full" />
                  ))}
                </div>
              ) : teamDevices && teamDevices.length > 0 ? (
                <Table aria-label="Devices assigned to this team">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Model</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Last Seen</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {teamDevices.map((device) => (
                      <TableRow key={device.id}>
                        <TableCell>
                          <Link to="/devices/$deviceId" params={{ deviceId: device.id }} className="font-medium text-primary hover:underline">
                            {device.name}
                          </Link>
                        </TableCell>
                        <TableCell>{device.deviceModel ?? "---"}</TableCell>
                        <TableCell>
                          <Badge variant={device.status === "online" ? "default" : "secondary"}>{device.status}</Badge>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">{device.lastSeenAt ? formatRelativeTimeShort(device.lastSeenAt) : "---"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <EmptyState icon={HardDrive} title="No devices assigned to this team" description="Devices assigned to this team will appear here." />
              )}
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Team Extensions */}
      <PageSection delay={0.3}>
        <SectionErrorBoundary name="Team Extensions">
          <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
            <CardHeader className="flex flex-row items-center justify-between">
              <div className="flex items-center gap-2">
                <CardTitle className="flex items-center gap-2">
                  <Phone className="h-5 w-5 text-muted-foreground" />
                  Team Extensions
                </CardTitle>
                {!extensionsLoading && teamExtensions && teamExtensions.length > 0 && (
                  <Badge variant="secondary" className="ml-1">
                    {teamExtensions.length}
                  </Badge>
                )}
              </div>
            </CardHeader>
            <CardContent>
              {extensionsLoading ? (
                <div className="space-y-3">
                  {Array.from({ length: 3 }).map((_, i) => (
                    // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
                    <Skeleton key={i} className="h-10 w-full" />
                  ))}
                </div>
              ) : teamExtensions && teamExtensions.length > 0 ? (
                <Table aria-label="Extensions in this team">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Extension</TableHead>
                      <TableHead>Display Name</TableHead>
                      <TableHead>Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {teamExtensions.map((ext) => (
                      <TableRow key={ext.id}>
                        <TableCell>
                          <Link to="/voice/extensions/$extensionId" params={{ extensionId: ext.id }} className="font-medium text-primary hover:underline">
                            {ext.extensionNumber}
                          </Link>
                        </TableCell>
                        <TableCell>{ext.displayName}</TableCell>
                        <TableCell>
                          <Badge variant={ext.isActive ? "default" : "secondary"}>{ext.isActive ? "Active" : "Inactive"}</Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <EmptyState icon={Phone} title="No extensions in this team" description="Extensions belonging to team members will appear here." />
              )}
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Danger Zone */}
      <PageSection delay={0.4}>
        <SectionErrorBoundary name="Danger Zone">
          <Card className="border-destructive/30 bg-card/80 shadow-md">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-destructive">
                <AlertTriangle className="h-4 w-4" />
                Danger Zone
              </CardTitle>
              <CardDescription>Irreversible and destructive actions for this team.</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between rounded-lg border border-destructive/20 bg-destructive/5 p-4">
                <div>
                  <p className="font-medium text-sm">Delete this team</p>
                  <p className="text-xs text-muted-foreground">Once deleted, this team and all member associations cannot be recovered.</p>
                </div>
                <Button variant="destructive" size="sm" onClick={() => setShowDeleteDialog(true)}>
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete
                </Button>
              </div>
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Delete confirmation dialog */}
      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete team?
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete <strong>{team.name}</strong> and remove all member associations. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteTeamMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className={buttonVariants({ variant: "destructive" })}
              disabled={deleteTeamMutation.isPending}
              onClick={() => {
                deleteTeamMutation.mutate(teamId, {
                  onSuccess: () => {
                    setShowDeleteDialog(false)
                    navigate({ to: "/teams" })
                  },
                })
              }}
            >
              {deleteTeamMutation.isPending ? "Deleting..." : "Delete team"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Unsaved changes dialog */}
      <AlertDialog open={blocker.status === "blocked"} onOpenChange={() => blocker.reset?.()}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Unsaved changes</AlertDialogTitle>
            <AlertDialogDescription>You have unsaved changes to team details. Are you sure you want to leave? Your changes will be lost.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => blocker.reset?.()}>Stay on page</AlertDialogCancel>
            <AlertDialogAction onClick={() => blocker.proceed?.()}>Discard changes</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </PageContainer>
  )
}
