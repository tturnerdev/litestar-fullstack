import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ArrowLeft, Check, Pencil, Trash2, X } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"
import { AdminNav } from "@/components/admin/admin-nav"
import { DeleteTeamDialog } from "@/components/admin/delete-team-dialog"
import { EditTeamDialog } from "@/components/admin/edit-team-dialog"
import { Badge } from "@/components/ui/badge"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { useAdminTeam, useAdminUpdateTeam } from "@/lib/api/hooks/admin"
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

function AdminTeamDetailPage() {
  const { teamId } = Route.useParams()
  const navigate = useNavigate()
  const { data, isLoading, isError } = useAdminTeam(teamId)
  const [editOpen, setEditOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Administration" title="Team Details" />
        <AdminNav />
        <PageSection>
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
          <Card>
            <CardHeader>
              <CardTitle>Team detail</CardTitle>
            </CardHeader>
            <CardContent className="text-muted-foreground">We could not load this team.</CardContent>
          </Card>
        </PageSection>
      </PageContainer>
    )
  }

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title={data.name}
        description="Manage team settings, members, and invitations."
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/admin">Admin</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/admin/teams">Teams</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbPage>{data.name}</BreadcrumbPage></BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => setEditOpen(true)}>
              <Pencil className="mr-2 h-4 w-4" /> Edit
            </Button>
            <Button variant="outline" size="sm" className="text-destructive hover:text-destructive" onClick={() => setDeleteOpen(true)}>
              <Trash2 className="mr-2 h-4 w-4" /> Delete
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to="/admin/teams">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to teams
              </Link>
            </Button>
          </div>
        }
      />
      <AdminNav />

      <PageSection>
        <Tabs defaultValue="overview">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="members">Members ({data.members?.length ?? 0})</TabsTrigger>
            <TabsTrigger value="invitations">Invitations</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6 pt-4">
            <TeamInfoCard
              teamId={teamId}
              name={data.name}
              description={data.description}
              slug={data.slug}
              ownerEmail={data.ownerEmail}
              memberCount={data.memberCount}
              isActive={data.isActive}
              createdAt={data.createdAt}
              updatedAt={data.updatedAt}
            />
          </TabsContent>

          <TabsContent value="members" className="pt-4">
            <MembersCard members={data.members ?? []} />
          </TabsContent>

          <TabsContent value="invitations" className="pt-4">
            <InvitationsCard teamId={teamId} />
          </TabsContent>
        </Tabs>
      </PageSection>

      <EditTeamDialog
        teamId={teamId}
        currentName={data.name}
        currentDescription={data.description}
        open={editOpen}
        onOpenChange={setEditOpen}
      />

      <DeleteTeamDialog
        teamId={teamId}
        teamName={data.name}
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        onDeleted={() => navigate({ to: "/admin/teams" })}
      />
    </PageContainer>
  )
}

/* ---------- Overview / Info Card with inline edit ---------- */

interface TeamInfoCardProps {
  teamId: string
  name: string
  description: string | null | undefined
  slug: string
  ownerEmail: string | null | undefined
  memberCount: number | undefined
  isActive: boolean | undefined
  createdAt: string
  updatedAt: string
}

function TeamInfoCard({ teamId, name, description, slug, ownerEmail, memberCount, isActive, createdAt, updatedAt }: TeamInfoCardProps) {
  const updateTeam = useAdminUpdateTeam(teamId)

  const [editingField, setEditingField] = useState<"name" | "description" | null>(null)
  const [editValue, setEditValue] = useState("")

  const startEdit = (field: "name" | "description", current: string) => {
    setEditingField(field)
    setEditValue(current)
  }

  const cancelEdit = () => {
    setEditingField(null)
    setEditValue("")
  }

  const saveEdit = () => {
    if (!editingField) return
    const payload: Record<string, unknown> = {}
    if (editingField === "name") {
      if (!editValue.trim()) return
      payload.name = editValue.trim()
    } else {
      payload.description = editValue.trim() || null
    }
    updateTeam.mutate(payload, { onSuccess: () => cancelEdit() })
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Team Information</CardTitle>
        <CardDescription>Core details for this team.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid gap-4 text-sm md:grid-cols-2">
          {/* Name */}
          <div className="space-y-1">
            <p className="text-muted-foreground">Name</p>
            {editingField === "name" ? (
              <div className="flex items-center gap-2">
                <Input value={editValue} onChange={(e) => setEditValue(e.target.value)} className="h-8" autoFocus />
                <Button variant="ghost" size="sm" className="h-8 w-8 p-0" onClick={saveEdit} disabled={updateTeam.isPending}>
                  <Check className="h-4 w-4" />
                </Button>
                <Button variant="ghost" size="sm" className="h-8 w-8 p-0" onClick={cancelEdit}>
                  <X className="h-4 w-4" />
                </Button>
              </div>
            ) : (
              <div className="group flex items-center gap-2">
                <p>{name}</p>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 w-6 p-0 opacity-0 transition-opacity group-hover:opacity-100"
                  onClick={() => startEdit("name", name)}
                >
                  <Pencil className="h-3 w-3" />
                </Button>
              </div>
            )}
          </div>

          {/* Slug */}
          <div className="space-y-1">
            <p className="text-muted-foreground">Slug</p>
            <p>{slug}</p>
          </div>

          {/* Owner */}
          <div className="space-y-1">
            <p className="text-muted-foreground">Owner</p>
            <p>{ownerEmail ?? "---"}</p>
          </div>

          {/* Members */}
          <div className="space-y-1">
            <p className="text-muted-foreground">Members</p>
            <p>{memberCount ?? 0}</p>
          </div>

          {/* Status */}
          <div className="space-y-1">
            <p className="text-muted-foreground">Status</p>
            <Badge variant={isActive ? "default" : "secondary"}>{isActive ? "Active" : "Inactive"}</Badge>
          </div>

          {/* Created */}
          <div className="space-y-1">
            <p className="text-muted-foreground">Created</p>
            <p>{new Date(createdAt).toLocaleString()}</p>
          </div>

          {/* Updated */}
          <div className="space-y-1">
            <p className="text-muted-foreground">Last Updated</p>
            <p>{new Date(updatedAt).toLocaleString()}</p>
          </div>
        </div>

        {/* Description - full width */}
        <div className="space-y-1">
          <p className="text-sm text-muted-foreground">Description</p>
          {editingField === "description" ? (
            <div className="space-y-2">
              <Textarea value={editValue} onChange={(e) => setEditValue(e.target.value)} rows={3} autoFocus />
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={saveEdit} disabled={updateTeam.isPending}>
                  {updateTeam.isPending ? "Saving..." : "Save"}
                </Button>
                <Button variant="ghost" size="sm" onClick={cancelEdit}>
                  Cancel
                </Button>
              </div>
            </div>
          ) : (
            <div className="group flex items-start gap-2">
              <p className="text-sm">{description || "No description provided."}</p>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 w-6 shrink-0 p-0 opacity-0 transition-opacity group-hover:opacity-100"
                onClick={() => startEdit("description", description ?? "")}
              >
                <Pencil className="h-3 w-3" />
              </Button>
            </div>
          )}
        </div>

        {/* Action buttons */}
        <div className="flex flex-wrap gap-2 border-t pt-4">
          <Button variant="outline" onClick={() => updateTeam.mutate({ is_active: !isActive })} disabled={updateTeam.isPending}>
            {isActive ? "Deactivate" : "Activate"}
          </Button>
        </div>
      </CardContent>
    </Card>
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
    }
  }>
}

function MembersCard({ members }: MembersCardProps) {
  if (members.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Members</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">This team has no members.</CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Members</CardTitle>
        <CardDescription>{members.length} member{members.length !== 1 ? "s" : ""} in this team.</CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Email</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Owner</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {members.map((member) => (
              <TableRow key={member.user.id}>
                <TableCell className="font-medium">
                  <Link
                    to="/admin/users/$userId"
                    params={{ userId: member.user.id }}
                    className="hover:underline"
                  >
                    {member.user.name ?? member.user.email}
                  </Link>
                </TableCell>
                <TableCell className="text-muted-foreground">{member.user.email}</TableCell>
                <TableCell>
                  <Badge variant="outline">{member.role}</Badge>
                </TableCell>
                <TableCell>
                  {member.isOwner ? <Badge variant="default">Owner</Badge> : "---"}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

/* ---------- Invitations Card ---------- */

function InvitationsCard({ teamId }: { teamId: string }) {
  const queryClient = useQueryClient()

  const { data, isLoading, isError } = useQuery({
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
      <Card>
        <CardHeader>
          <CardTitle>Invitations</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">Could not load invitations.</CardContent>
      </Card>
    )
  }

  const pending = data.items.filter((inv) => !inv.isAccepted)
  const accepted = data.items.filter((inv) => inv.isAccepted)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Invitations</CardTitle>
        <CardDescription>
          {pending.length} pending, {accepted.length} accepted
        </CardDescription>
      </CardHeader>
      <CardContent>
        {data.items.length === 0 ? (
          <p className="text-sm text-muted-foreground">No invitations for this team.</p>
        ) : (
          <Table>
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
                  <TableCell className="font-medium">{inv.email}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{inv.role}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant={inv.isAccepted ? "default" : "secondary"}>
                      {inv.isAccepted ? "Accepted" : "Pending"}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{new Date(inv.createdAt).toLocaleDateString()}</TableCell>
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
        )}
      </CardContent>
    </Card>
  )
}
