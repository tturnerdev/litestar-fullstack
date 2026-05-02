import { createFileRoute, Link, useBlocker, useNavigate } from "@tanstack/react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  AlertCircle,
  ArrowLeft,
  Calendar,
  Clock,
  Copy,
  Hash,
  Loader2,
  Mail,
  MoreHorizontal,
  Pencil,
  Save,
  Shield,
  Trash2,
  UserCheck,
  UserX,
  Users,
  X,
} from "lucide-react"
import { useCallback, useEffect, useMemo, useState } from "react"
import { toast } from "sonner"
import { AdminNav } from "@/components/admin/admin-nav"
import { DeleteTeamDialog } from "@/components/admin/delete-team-dialog"
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
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import { CopyButton } from "@/components/ui/copy-button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { useAdminTeam, useAdminUpdateTeam } from "@/lib/api/hooks/admin"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import {
  deleteTeamInvitation,
  listTeamInvitations,
  type DeleteTeamInvitationData,
  type ListTeamInvitationsData,
  type TeamInvitation,
} from "@/lib/generated/api"

export const Route = createFileRoute("/_app/admin/teams/$teamId")({
  component: AdminTeamDetailPage,
})

// -- Helpers -----------------------------------------------------------------

function getTeamInitials(name: string): string {
  const parts = name.trim().split(/\s+/)
  if (parts.length >= 2) {
    return (parts[0][0] + parts[1][0]).toUpperCase()
  }
  return parts[0].slice(0, 2).toUpperCase()
}


// -- Reusable sub-components ------------------------------------------------

function TimestampField({
  label,
  value,
  icon: Icon,
}: {
  label: string
  value: string | null | undefined
  icon?: React.ComponentType<{ className?: string }>
}) {
  if (!value) {
    return (
      <div>
        <p className="text-sm text-muted-foreground">{label}</p>
        <p className="text-sm">---</p>
      </div>
    )
  }

  return (
    <div>
      <p className="text-sm text-muted-foreground">{label}</p>
      <Tooltip>
        <TooltipTrigger asChild>
          <p className="inline-flex cursor-default items-center gap-1.5 text-sm">
            {Icon && <Icon className="h-3.5 w-3.5 text-muted-foreground" />}
            {formatRelativeTimeShort(value)}
          </p>
        </TooltipTrigger>
        <TooltipContent>{formatDateTime(value)}</TooltipContent>
      </Tooltip>
    </div>
  )
}

function SectionHeading({
  icon: Icon,
  title,
  description,
  actions,
}: {
  icon: React.ComponentType<{ className?: string }>
  title: string
  description?: string
  actions?: React.ReactNode
}) {
  return (
    <div className="flex items-start justify-between">
      <div className="space-y-1">
        <h3 className="flex items-center gap-2 text-lg font-semibold tracking-tight">
          <Icon className="h-5 w-5 text-muted-foreground" />
          {title}
        </h3>
        {description && <p className="text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions}
    </div>
  )
}

// -- Main page component ----------------------------------------------------

function AdminTeamDetailPage() {
  const { teamId } = Route.useParams()
  const navigate = useNavigate()
  const { data, isLoading, isError, refetch } = useAdminTeam(teamId)
  useDocumentTitle(data?.name ? `Admin - ${data.name}` : "Admin - Team Details")
  const updateTeam = useAdminUpdateTeam(teamId)
  const [deleteOpen, setDeleteOpen] = useState(false)

  // Inline editing state
  const [editing, setEditing] = useState(false)
  const [editName, setEditName] = useState("")
  const [editDescription, setEditDescription] = useState("")

  // Sync edit fields from current data
  const syncEditFields = useCallback(() => {
    if (data) {
      setEditName(data.name)
      setEditDescription(data.description ?? "")
    }
  }, [data])

  useEffect(() => {
    syncEditFields()
  }, [syncEditFields])

  // Dirty check
  const formDirty = useMemo(() => {
    if (!editing || !data) return false
    return (
      editName !== data.name ||
      editDescription !== (data.description ?? "")
    )
  }, [editing, data, editName, editDescription])

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
    if (!data) return
    const trimmedName = editName.trim()
    if (!trimmedName) return

    const payload: Record<string, unknown> = {}

    if (trimmedName !== data.name) payload.name = trimmedName
    if (editDescription !== (data.description ?? "")) {
      payload.description = editDescription || null
    }

    if (Object.keys(payload).length === 0) {
      setEditing(false)
      return
    }

    updateTeam.mutate(payload, {
      onSuccess: () => {
        setEditing(false)
      },
    })
  }

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Administration" title="Team Details" />
        <AdminNav />
        <PageSection>
          <SkeletonCard />
          <SkeletonCard />
        </PageSection>
      </PageContainer>
    )
  }

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Administration"
          title="Team Details"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/admin/teams">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to teams
              </Link>
            </Button>
          }
        />
        <AdminNav />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load team"
            description="The team may have been deleted or you may not have permission to view it."
            action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
          />
        </PageSection>
      </PageContainer>
    )
  }

  const members = data.members ?? []
  const memberCount = data.memberCount ?? members.length

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title={data.name}
        description="View and manage team settings, members, and invitations."
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
                  <Link to="/admin">Admin</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/admin/teams">Teams</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>{data.name}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-2">
            {editing ? (
              <>
                <Button variant="outline" size="sm" onClick={handleCancelEditing} disabled={updateTeam.isPending}>
                  <X className="mr-2 h-4 w-4" /> Cancel
                </Button>
                <Button size="sm" onClick={handleSaveEditing} disabled={updateTeam.isPending || !editName.trim()}>
                  {updateTeam.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
                  {updateTeam.isPending ? "Saving..." : "Save"}
                </Button>
              </>
            ) : (
              <Button variant="outline" size="sm" onClick={handleStartEditing}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
              </Button>
            )}
            <Button variant="outline" size="sm" asChild>
              <Link to="/admin/teams">
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
                {!editing && (
                  <DropdownMenuItem onClick={handleStartEditing}>
                    <Pencil className="mr-2 h-4 w-4" />
                    Edit Team
                  </DropdownMenuItem>
                )}
                <DropdownMenuItem
                  onClick={() => {
                    navigator.clipboard.writeText(teamId)
                    toast.success("Team ID copied to clipboard")
                  }}
                >
                  <Copy className="mr-2 h-4 w-4" />
                  Copy Team ID
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  className="text-destructive focus:text-destructive"
                  onClick={() => setDeleteOpen(true)}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete Team
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        }
      />
      <AdminNav />

      {/* Hero section */}
      <PageSection>
        <Card className="overflow-hidden">
          <div className="h-24 bg-gradient-to-r from-primary/20 via-primary/10 to-transparent" />
          <CardContent className="relative -mt-12 pb-6">
            {editing && formDirty && (
              <div className="mb-4 mt-14 flex items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-700 dark:text-amber-400">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-amber-500" />
                You have unsaved changes
              </div>
            )}
            <div className="flex flex-col items-center gap-5 sm:flex-row sm:items-end">
              <div className="rounded-full bg-background p-1 shadow-md ring-2 ring-background">
                <Avatar className="h-24 w-24 text-3xl">
                  <AvatarFallback className="bg-primary/10 text-primary text-3xl font-semibold">
                    {getTeamInitials(editing ? editName || data.name : data.name)}
                  </AvatarFallback>
                </Avatar>
              </div>

              <div className="flex-1 space-y-1.5 text-center sm:pb-1 sm:text-left">
                {editing ? (
                  <div className="space-y-3">
                    <div className="space-y-2">
                      <Label htmlFor="edit-team-name">Name</Label>
                      <Input
                        id="edit-team-name"
                        value={editName}
                        onChange={(e) => setEditName(e.target.value)}
                        placeholder="Team name"
                        disabled={updateTeam.isPending}
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
                        disabled={updateTeam.isPending}
                        maxLength={500}
                        rows={3}
                      />
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="flex flex-col items-center gap-2 sm:flex-row sm:flex-wrap">
                      <h2 className="text-2xl font-semibold tracking-tight">{data.name}</h2>
                      <Badge
                        variant={data.isActive ? "default" : "secondary"}
                        className={
                          data.isActive
                            ? "gap-1 bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400"
                            : "gap-1"
                        }
                      >
                        {data.isActive ? (
                          <>
                            <UserCheck className="h-3 w-3" />
                            Active
                          </>
                        ) : (
                          <>
                            <UserX className="h-3 w-3" />
                            Inactive
                          </>
                        )}
                      </Badge>
                    </div>

                    <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-1 text-sm text-muted-foreground sm:justify-start">
                      {data.slug && (
                        <span className="inline-flex items-center gap-1.5">
                          <Hash className="h-3.5 w-3.5" />
                          {data.slug}
                          <CopyButton value={data.slug} label="slug" />
                        </span>
                      )}
                      {data.ownerEmail && (
                        <span className="inline-flex items-center gap-1.5">
                          <Mail className="h-3.5 w-3.5" />
                          {data.ownerEmail}
                          <CopyButton value={data.ownerEmail} label="owner email" />
                        </span>
                      )}
                      <span className="inline-flex items-center gap-1.5">
                        <Users className="h-3.5 w-3.5" />
                        {memberCount} member{memberCount !== 1 ? "s" : ""}
                      </span>
                    </div>

                    {data.description && (
                      <p className="text-sm text-muted-foreground">{data.description}</p>
                    )}
                  </>
                )}
              </div>
            </div>

            <Separator className="my-4" />

            {/* Team ID with copy */}
            <div className="flex items-center justify-end gap-1 text-xs text-muted-foreground">
              <span className="font-mono">{teamId.slice(0, 8)}...</span>
              <CopyButton value={teamId} label="team ID" />
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Team Info + Statistics side-by-side */}
      <PageSection delay={0.1}>
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Team Info */}
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Users className="h-5 w-5 text-muted-foreground" />
                <CardTitle>Team Info</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 text-sm sm:grid-cols-2">
                <div>
                  <p className="text-muted-foreground">Name</p>
                  {editing ? (
                    <Input
                      value={editName}
                      onChange={(e) => setEditName(e.target.value)}
                      placeholder="Team name"
                      disabled={updateTeam.isPending}
                      maxLength={100}
                      className="mt-1"
                    />
                  ) : (
                    <p className="font-medium">{data.name}</p>
                  )}
                </div>
                <div>
                  <p className="text-muted-foreground">Slug</p>
                  <div className="flex items-center gap-1">
                    <p className="font-mono text-xs">{data.slug}</p>
                    {data.slug && <CopyButton value={data.slug} label="slug" />}
                  </div>
                </div>
                <div>
                  <p className="text-muted-foreground">Owner</p>
                  <div className="flex items-center gap-1">
                    <p>{data.ownerEmail ?? "---"}</p>
                    {data.ownerEmail && <CopyButton value={data.ownerEmail} label="owner email" />}
                  </div>
                </div>
                <div>
                  <p className="text-muted-foreground">Status</p>
                  <Badge
                    variant={data.isActive ? "default" : "secondary"}
                    className={
                      data.isActive
                        ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400"
                        : ""
                    }
                  >
                    {data.isActive ? "Active" : "Inactive"}
                  </Badge>
                </div>
                <div className="sm:col-span-2">
                  <p className="text-muted-foreground">Description</p>
                  {editing ? (
                    <Textarea
                      value={editDescription}
                      onChange={(e) => setEditDescription(e.target.value)}
                      placeholder="Optional description"
                      disabled={updateTeam.isPending}
                      maxLength={500}
                      rows={3}
                      className="mt-1"
                    />
                  ) : (
                    <p className="text-sm">{data.description || "No description provided."}</p>
                  )}
                </div>
                <div>
                  <p className="text-muted-foreground">Team ID</p>
                  <div className="flex items-center gap-1">
                    <p className="font-mono text-xs">{teamId.slice(0, 8)}...</p>
                    <CopyButton value={teamId} label="team ID" />
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Statistics */}
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Clock className="h-5 w-5 text-muted-foreground" />
                <CardTitle>Statistics</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 text-sm sm:grid-cols-2">
                <div>
                  <p className="text-muted-foreground">Total members</p>
                  <p className="flex items-center gap-1.5 text-xl font-semibold">
                    <Users className="h-4 w-4 text-muted-foreground" />
                    {memberCount}
                  </p>
                </div>
                <div>
                  <p className="text-muted-foreground">Owner</p>
                  <p className="text-sm">{data.ownerEmail ?? "No owner"}</p>
                </div>
                <TimestampField label="Created" value={data.createdAt} icon={Calendar} />
                <TimestampField label="Last updated" value={data.updatedAt} icon={Clock} />
              </div>
            </CardContent>
          </Card>
        </div>
      </PageSection>

      <Separator />

      {/* Members */}
      <PageSection delay={0.15}>
        <SectionHeading
          icon={Users}
          title="Members"
          description={`${memberCount} member${memberCount !== 1 ? "s" : ""} in this team.`}
        />
        <MembersCard members={members} />
      </PageSection>

      <Separator />

      {/* Invitations */}
      <PageSection delay={0.2}>
        <SectionHeading
          icon={Mail}
          title="Invitations"
          description="Pending and accepted team invitations."
        />
        <InvitationsCard teamId={teamId} />
      </PageSection>

      <Separator />

      {/* Admin Actions */}
      <PageSection delay={0.25}>
        <SectionHeading
          icon={Shield}
          title="Admin Actions"
          description="Toggle team properties and manage access."
        />
        <Card>
          <CardContent className="divide-y pt-6">
            {/* Active toggle */}
            <div className="flex items-center justify-between py-4 first:pt-0 last:pb-0">
              <div className="space-y-0.5">
                <p className="text-sm font-medium">Team active</p>
                <p className="text-xs text-muted-foreground">
                  {data.isActive
                    ? "Team is active and accessible to all members."
                    : "Team is deactivated and members cannot access it."}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <Badge
                  variant={data.isActive ? "default" : "secondary"}
                  className={
                    data.isActive
                      ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400"
                      : ""
                  }
                >
                  {data.isActive ? "Active" : "Inactive"}
                </Badge>
                <Switch
                  checked={data.isActive ?? false}
                  onCheckedChange={() => updateTeam.mutate({ is_active: !data.isActive })}
                  disabled={updateTeam.isPending}
                />
              </div>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      <Separator />

      {/* Activity History (Audit Trail) */}
      <PageSection delay={0.3}>
        <Card>
          <CardHeader>
            <CardTitle>Activity History</CardTitle>
          </CardHeader>
          <CardContent>
            <EntityActivityPanel targetType="team" targetId={teamId} />
          </CardContent>
        </Card>
      </PageSection>

      <Separator />

      {/* Danger Zone */}
      <PageSection delay={0.35}>
        <Card className="border-destructive/30">
          <CardHeader>
            <CardTitle className="text-destructive">Danger Zone</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">Delete this team</p>
                <p className="text-sm text-muted-foreground">
                  Permanently remove <strong>{data.name}</strong> and all associated data, memberships, and invitations. This action cannot be undone.
                </p>
              </div>
              <Button variant="destructive" size="sm" onClick={() => setDeleteOpen(true)}>
                <Trash2 className="mr-2 h-4 w-4" />
                Delete
              </Button>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Dialogs */}
      <DeleteTeamDialog
        teamId={teamId}
        teamName={data.name}
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        onDeleted={() => navigate({ to: "/admin/teams" })}
      />

      {/* Unsaved changes dialog */}
      <AlertDialog open={blocker.status === "blocked"} onOpenChange={() => blocker.reset?.()}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Unsaved changes</AlertDialogTitle>
            <AlertDialogDescription>
              You have unsaved changes to team details. Are you sure you want to leave? Your changes will be lost.
            </AlertDialogDescription>
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

/* ---------- Members Card ---------- */

interface MembersCardProps {
  members: Array<{
    isOwner: boolean
    role: string
    user: {
      id: string
      email: string
      name?: string | null
      avatarUrl?: string | null
    }
  }>
}

function MembersCard({ members }: MembersCardProps) {
  if (members.length === 0) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-sm text-muted-foreground">
          This team has no members.
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardContent className="pt-6">
        <div className="overflow-x-auto">
        <Table aria-label="Team members">
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Email</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Owner</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {members.map((member) => (
              <TableRow key={member.user.id}>
                <TableCell className="font-medium">
                  <div className="flex items-center gap-2">
                    <Avatar className="h-7 w-7 text-xs">
                      <AvatarFallback className="bg-primary/10 text-primary text-xs">
                        {(member.user.name ?? member.user.email).slice(0, 2).toUpperCase()}
                      </AvatarFallback>
                    </Avatar>
                    <Link
                      to="/admin/users/$userId"
                      params={{ userId: member.user.id }}
                      className="hover:underline"
                    >
                      {member.user.name ?? member.user.email.split("@")[0]}
                    </Link>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-1 text-muted-foreground">
                    {member.user.email}
                    <CopyButton value={member.user.email} label="email" />
                  </div>
                </TableCell>
                <TableCell>
                  <Badge variant="outline" className="capitalize">{member.role}</Badge>
                </TableCell>
                <TableCell>
                  {member.isOwner ? (
                    <Badge className="gap-1 bg-amber-100 text-amber-700 hover:bg-amber-100 dark:bg-amber-900/30 dark:text-amber-400">
                      Owner
                    </Badge>
                  ) : (
                    <span className="text-muted-foreground">---</span>
                  )}
                </TableCell>
                <TableCell className="text-right">
                  <Button asChild variant="ghost" size="sm">
                    <Link to="/admin/users/$userId" params={{ userId: member.user.id }}>
                      View user
                    </Link>
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        </div>
      </CardContent>
    </Card>
  )
}

/* ---------- Invitations Card ---------- */

function InvitationsCard({ teamId }: { teamId: string }) {
  const queryClient = useQueryClient()

  const { data, isLoading, isError, refetch: refetchInvitations } = useQuery({
    queryKey: ["admin", "team", teamId, "invitations"],
    queryFn: async () => {
      const query = { pageSize: 50 } as unknown as ListTeamInvitationsData["query"]
      const response = await listTeamInvitations({ path: { team_id: teamId }, query })
      return response.data as { items: TeamInvitation[]; total: number }
    },
  })

  const revokeInvitation = useMutation({
    mutationFn: async (invitationId: string) => {
      await deleteTeamInvitation({
        path: { team_id: teamId, invitation_id: invitationId } as DeleteTeamInvitationData["path"],
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "team", teamId, "invitations"] })
      toast.success("Invitation revoked")
    },
    onError: (error) => {
      toast.error("Unable to revoke invitation", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })

  if (isLoading) {
    return <SkeletonCard />
  }

  if (isError || !data) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load invitations"
        description="Something went wrong. Please try again."
        action={<Button variant="outline" size="sm" onClick={() => refetchInvitations()}>Try again</Button>}
      />
    )
  }

  const pending = data.items.filter((inv) => !inv.isAccepted)
  const accepted = data.items.filter((inv) => inv.isAccepted)

  if (data.items.length === 0) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-sm text-muted-foreground">
          No invitations for this team.
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          {pending.length} pending, {accepted.length} accepted
        </div>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
        <Table aria-label="Team invitations">
          <TableHeader>
            <TableRow>
              <TableHead>Email</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Sent</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.items.map((inv) => (
              <TableRow key={inv.id}>
                <TableCell className="font-medium">
                  <div className="flex items-center gap-1">
                    {inv.email}
                    <CopyButton value={inv.email} label="email" />
                  </div>
                </TableCell>
                <TableCell>
                  <Badge variant="outline">{inv.role}</Badge>
                </TableCell>
                <TableCell>
                  <Badge variant={inv.isAccepted ? "default" : "secondary"}>
                    {inv.isAccepted ? "Accepted" : "Pending"}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className="cursor-default text-muted-foreground">
                        {formatRelativeTimeShort(inv.createdAt)}
                      </span>
                    </TooltipTrigger>
                    <TooltipContent>{formatDateTime(inv.createdAt)}</TooltipContent>
                  </Tooltip>
                </TableCell>
                <TableCell className="text-right">
                  {!inv.isAccepted && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-destructive hover:text-destructive"
                      onClick={() => revokeInvitation.mutate(inv.id)}
                      disabled={revokeInvitation.isPending}
                    >
                      Revoke
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        </div>
      </CardContent>
    </Card>
  )
}
