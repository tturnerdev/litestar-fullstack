import { createFileRoute, Link } from "@tanstack/react-router"
import { ArrowLeft, Pencil, Shield, Trash2, UserCheck, UserX } from "lucide-react"
import { useState } from "react"
import { AdminNav } from "@/components/admin/admin-nav"
import { DeleteUserDialog } from "@/components/admin/delete-user-dialog"
import { EditUserDialog } from "@/components/admin/edit-user-dialog"
import { ManageRolesDialog } from "@/components/admin/manage-roles-dialog"
import { ToggleUserStatusDialog } from "@/components/admin/toggle-user-status-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useAdminUpdateUser, useAdminUser, useAdminUserAuditLogs } from "@/lib/api/hooks/admin"

export const Route = createFileRoute("/_app/admin/users/$userId")({
  component: AdminUserDetailPage,
})

function AdminUserDetailPage() {
  const { userId } = Route.useParams()
  const { data, isLoading, isError } = useAdminUser(userId)
  const updateUser = useAdminUpdateUser(userId)
  const [editOpen, setEditOpen] = useState(false)
  const [rolesOpen, setRolesOpen] = useState(false)
  const [statusOpen, setStatusOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [auditPage, setAuditPage] = useState(1)
  const { data: auditData, isLoading: auditLoading } = useAdminUserAuditLogs(userId, auditPage, 10)

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Administration" title="User Details" />
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
          title="User Details"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/admin/users">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to users
              </Link>
            </Button>
          }
        />
        <AdminNav />
        <PageSection>
          <Card>
            <CardHeader>
              <CardTitle>User detail</CardTitle>
            </CardHeader>
            <CardContent className="text-muted-foreground">We could not load this user.</CardContent>
          </Card>
        </PageSection>
      </PageContainer>
    )
  }

  const auditTotalPages = auditData ? Math.max(1, Math.ceil(auditData.total / 10)) : 1

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title={data.name ?? data.email}
        description="Manage user account settings and permissions."
        actions={
          <Button variant="outline" size="sm" asChild>
            <Link to="/admin/users">
              <ArrowLeft className="mr-2 h-4 w-4" /> Back to users
            </Link>
          </Button>
        }
      />
      <AdminNav />

      {/* User Info + Quick Actions */}
      <PageSection>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Account Details</CardTitle>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => setEditOpen(true)}>
                <Pencil className="mr-2 h-4 w-4" />
                Edit
              </Button>
              <Button variant="outline" size="sm" onClick={() => setRolesOpen(true)}>
                <Shield className="mr-2 h-4 w-4" />
                Roles
              </Button>
              <Button variant="outline" size="sm" onClick={() => setStatusOpen(true)}>
                {data.isActive ? (
                  <>
                    <UserX className="mr-2 h-4 w-4" />
                    Deactivate
                  </>
                ) : (
                  <>
                    <UserCheck className="mr-2 h-4 w-4" />
                    Activate
                  </>
                )}
              </Button>
              <Button variant="destructive" size="sm" onClick={() => setDeleteOpen(true)}>
                <Trash2 className="mr-2 h-4 w-4" />
                Delete
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 text-sm md:grid-cols-3">
              <div>
                <p className="text-muted-foreground">Email</p>
                <p>{data.email}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Username</p>
                <p>{data.username ?? "---"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Name</p>
                <p>{data.name ?? "---"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Phone</p>
                <p>{data.phone ?? "---"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Status</p>
                <Badge variant={data.isActive ? "default" : "secondary"}>
                  {data.isActive ? "Active" : "Inactive"}
                </Badge>
              </div>
              <div>
                <p className="text-muted-foreground">Superuser</p>
                <div className="flex items-center gap-2">
                  {data.isSuperuser ? (
                    <Badge variant="destructive">Yes</Badge>
                  ) : (
                    <span>No</span>
                  )}
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 px-2 text-xs"
                    onClick={() => updateUser.mutate({ is_superuser: !data.isSuperuser })}
                    disabled={updateUser.isPending}
                  >
                    {data.isSuperuser ? "Remove" : "Grant"}
                  </Button>
                </div>
              </div>
              <div>
                <p className="text-muted-foreground">Email verified</p>
                <div className="flex items-center gap-2">
                  <Badge variant={data.isVerified ? "default" : "outline"}>
                    {data.isVerified ? "Verified" : "Unverified"}
                  </Badge>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 px-2 text-xs"
                    onClick={() => updateUser.mutate({ is_verified: !data.isVerified })}
                    disabled={updateUser.isPending}
                  >
                    {data.isVerified ? "Revoke" : "Verify"}
                  </Button>
                </div>
              </div>
              <div>
                <p className="text-muted-foreground">MFA enabled</p>
                <p>{data.isTwoFactorEnabled ? "Yes" : "No"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Has password</p>
                <p>{data.hasPassword ? "Yes" : "No (OAuth only)"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Login count</p>
                <p>{data.loginCount ?? 0}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Joined</p>
                <p>{data.joinedAt ? new Date(data.joinedAt).toLocaleDateString() : "---"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Last updated</p>
                <p>{new Date(data.updatedAt).toLocaleString()}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Roles */}
      <PageSection>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Roles</CardTitle>
            <Button variant="outline" size="sm" onClick={() => setRolesOpen(true)}>
              Manage roles
            </Button>
          </CardHeader>
          <CardContent>
            {(data.roles ?? []).length === 0 ? (
              <p className="text-sm text-muted-foreground">No roles assigned.</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {(data.roles ?? []).map((role) => (
                  <Badge key={role.roleId} variant="secondary">
                    {role.roleName}
                    <span className="ml-1 text-xs text-muted-foreground">
                      (since {new Date(role.assignedAt).toLocaleDateString()})
                    </span>
                  </Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </PageSection>

      {/* Team Memberships */}
      <PageSection>
        <Card>
          <CardHeader>
            <CardTitle>Team Memberships</CardTitle>
          </CardHeader>
          <CardContent>
            {(data.teams ?? []).length === 0 ? (
              <p className="text-sm text-muted-foreground">Not a member of any teams.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Team</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Owner</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(data.teams ?? []).map((team) => (
                    <TableRow key={team.teamId}>
                      <TableCell className="font-medium">{team.teamName}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{team.role ?? "member"}</Badge>
                      </TableCell>
                      <TableCell>{team.isOwner ? "Yes" : "No"}</TableCell>
                      <TableCell className="text-right">
                        <Button asChild variant="ghost" size="sm">
                          <Link to="/admin/teams/$teamId" params={{ teamId: team.teamId }}>
                            View team
                          </Link>
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </PageSection>

      {/* OAuth Accounts */}
      {(data.oauthAccounts ?? []).length > 0 && (
        <PageSection>
          <Card>
            <CardHeader>
              <CardTitle>Linked OAuth Accounts</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Provider</TableHead>
                    <TableHead>Account email</TableHead>
                    <TableHead>Account ID</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(data.oauthAccounts ?? []).map((account) => (
                    <TableRow key={account.id}>
                      <TableCell className="font-medium capitalize">{account.oauthName}</TableCell>
                      <TableCell>{account.accountEmail}</TableCell>
                      <TableCell className="text-muted-foreground">{account.accountId}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </PageSection>
      )}

      {/* Recent Audit Log */}
      <PageSection>
        <Card>
          <CardHeader>
            <CardTitle>Recent Activity</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {auditLoading ? (
              <p className="text-sm text-muted-foreground">Loading audit log...</p>
            ) : !auditData || auditData.items.length === 0 ? (
              <p className="text-sm text-muted-foreground">No audit entries found for this user.</p>
            ) : (
              <>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Action</TableHead>
                      <TableHead>Actor</TableHead>
                      <TableHead>Target</TableHead>
                      <TableHead>IP Address</TableHead>
                      <TableHead>Date</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {auditData.items.map((entry) => (
                      <TableRow key={entry.id}>
                        <TableCell>
                          <Badge variant="outline">{entry.action}</Badge>
                        </TableCell>
                        <TableCell className="text-muted-foreground">{entry.actorEmail ?? entry.actorId ?? "System"}</TableCell>
                        <TableCell className="text-muted-foreground">{entry.targetLabel ?? entry.targetId ?? "---"}</TableCell>
                        <TableCell className="text-muted-foreground">{entry.ipAddress ?? "---"}</TableCell>
                        <TableCell className="text-muted-foreground">{new Date(entry.createdAt).toLocaleString()}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                {auditData.total > 10 && (
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-muted-foreground">
                      Page {auditPage} of {auditTotalPages}
                    </p>
                    <div className="flex gap-2">
                      <Button variant="outline" size="sm" onClick={() => setAuditPage((p) => Math.max(1, p - 1))} disabled={auditPage <= 1}>
                        Previous
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => setAuditPage((p) => Math.min(auditTotalPages, p + 1))} disabled={auditPage >= auditTotalPages}>
                        Next
                      </Button>
                    </div>
                  </div>
                )}
              </>
            )}
          </CardContent>
        </Card>
      </PageSection>

      {/* Dialogs */}
      <EditUserDialog user={data} open={editOpen} onOpenChange={setEditOpen} />
      <ManageRolesDialog userId={userId} userEmail={data.email} open={rolesOpen} onOpenChange={setRolesOpen} />
      <ToggleUserStatusDialog userId={userId} userEmail={data.email} isActive={data.isActive ?? true} open={statusOpen} onOpenChange={setStatusOpen} />
      <DeleteUserDialog userId={userId} userEmail={data.email} open={deleteOpen} onOpenChange={setDeleteOpen} navigateOnDelete />
    </PageContainer>
  )
}
