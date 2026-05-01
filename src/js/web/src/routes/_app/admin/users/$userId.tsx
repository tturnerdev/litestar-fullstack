import { createFileRoute, Link } from "@tanstack/react-router"
import {
  ArrowLeft,
  BadgeCheck,
  Calendar,
  Clock,
  KeyRound,
  Link2,
  Lock,
  LogIn,
  Mail,
  Pencil,
  Phone,
  Shield,
  ShieldAlert,
  Trash2,
  User as UserIcon,
  UserCheck,
  UserX,
  Users,
} from "lucide-react"
import { useState } from "react"
import { AdminNav } from "@/components/admin/admin-nav"
import { DeleteUserDialog } from "@/components/admin/delete-user-dialog"
import { EditUserDialog } from "@/components/admin/edit-user-dialog"
import { ManageRolesDialog } from "@/components/admin/manage-roles-dialog"
import { ToggleUserStatusDialog } from "@/components/admin/toggle-user-status-dialog"
import { UserActivityTimeline } from "@/components/admin/user-activity-timeline"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
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
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { CopyButton } from "@/components/ui/copy-button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useAdminUpdateUser, useAdminUser } from "@/lib/api/hooks/admin"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"

export const Route = createFileRoute("/_app/admin/users/$userId")({
  component: AdminUserDetailPage,
})

// -- Helpers -----------------------------------------------------------------

function getInitials(name: string | null | undefined, email: string): string {
  if (name) {
    const parts = name.trim().split(/\s+/)
    if (parts.length >= 2) {
      return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase()
    }
    return parts[0].slice(0, 2).toUpperCase()
  }
  return email.slice(0, 2).toUpperCase()
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

function AdminUserDetailPage() {
  const { userId } = Route.useParams()
  const { data, isLoading, isError } = useAdminUser(userId)
  useDocumentTitle(data?.name || data?.email ? `Admin - ${data.name || data.email}` : "Admin - User Details")
  const updateUser = useAdminUpdateUser(userId)
  const [editOpen, setEditOpen] = useState(false)
  const [rolesOpen, setRolesOpen] = useState(false)
  const [statusOpen, setStatusOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Administration" title="User Details" />
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
              <CardTitle>User not found</CardTitle>
            </CardHeader>
            <CardContent className="text-muted-foreground">
              We could not load this user. They may have been deleted or you may not have permission to view them.
            </CardContent>
          </Card>
        </PageSection>
      </PageContainer>
    )
  }

  const displayName = data.name || data.email.split("@")[0]
  const initials = getInitials(data.name, data.email)
  const roleNames = (data.roles ?? []).map((r) => r.roleName)

  const securityIndicators = [
    {
      enabled: !!data.isVerified,
      icon: BadgeCheck,
      label: "Verified",
      enabledText: data.verifiedAt ? `Email verified on ${new Date(data.verifiedAt).toLocaleDateString()}` : "Email verified",
      disabledText: "Email not verified",
    },
    {
      enabled: !!data.isTwoFactorEnabled,
      icon: Shield,
      label: "MFA",
      enabledText: "Multi-factor authentication enabled",
      disabledText: "MFA not enabled",
    },
    {
      enabled: !!data.hasPassword,
      icon: Lock,
      label: "Password",
      enabledText: "Password authentication set",
      disabledText: "No password (OAuth only)",
    },
    {
      enabled: (data.oauthAccounts?.length ?? 0) > 0,
      icon: Link2,
      label: `${data.oauthAccounts?.length ?? 0} linked`,
      enabledText: `${data.oauthAccounts?.length ?? 0} connected OAuth account${(data.oauthAccounts?.length ?? 0) !== 1 ? "s" : ""}`,
      disabledText: "No connected OAuth accounts",
    },
  ]

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title={displayName}
        description="View and manage user account, roles, and permissions."
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
                  <Link to="/admin/users">Users</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>{displayName}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => setEditOpen(true)}>
              <Pencil className="mr-2 h-4 w-4" />
              Edit
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to="/admin/users">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
          </div>
        }
      />
      <AdminNav />

      {/* Hero section */}
      <PageSection>
        <Card className="overflow-hidden">
          <div className="h-24 bg-gradient-to-r from-primary/20 via-primary/10 to-transparent" />
          <CardContent className="relative -mt-12 pb-6">
            <div className="flex flex-col items-center gap-5 sm:flex-row sm:items-end">
              <div className="rounded-full bg-background p-1 shadow-md ring-2 ring-background">
                <Avatar className="h-24 w-24 text-3xl">
                  <AvatarImage src={undefined} alt={displayName} />
                  <AvatarFallback className="bg-primary/10 text-primary text-3xl font-semibold">
                    {initials}
                  </AvatarFallback>
                </Avatar>
              </div>

              <div className="flex-1 space-y-1.5 text-center sm:pb-1 sm:text-left">
                <div className="flex flex-col items-center gap-2 sm:flex-row sm:flex-wrap">
                  <h2 className="text-2xl font-semibold tracking-tight">{displayName}</h2>
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
                  {data.isSuperuser && (
                    <Badge variant="destructive" className="gap-1">
                      <ShieldAlert className="h-3 w-3" />
                      Superuser
                    </Badge>
                  )}
                  {roleNames.map((role) => (
                    <Badge key={role} variant="outline" className="gap-1 capitalize">
                      <KeyRound className="h-3 w-3" />
                      {role}
                    </Badge>
                  ))}
                </div>

                <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-1 text-sm text-muted-foreground sm:justify-start">
                  <span className="inline-flex items-center gap-1.5">
                    <Mail className="h-3.5 w-3.5" />
                    {data.email}
                    <CopyButton value={data.email} label="email" />
                  </span>
                  {data.username && (
                    <span className="inline-flex items-center gap-1.5">
                      <UserIcon className="h-3.5 w-3.5" />
                      @{data.username}
                    </span>
                  )}
                  {data.phone && (
                    <span className="inline-flex items-center gap-1.5">
                      <Phone className="h-3.5 w-3.5" />
                      {data.phone}
                    </span>
                  )}
                </div>
              </div>
            </div>

            <Separator className="my-4" />

            <div className="flex flex-wrap items-center justify-center gap-4 sm:justify-start">
              {securityIndicators.map((indicator) => {
                const Icon = indicator.icon
                return (
                  <Tooltip key={indicator.label}>
                    <TooltipTrigger asChild>
                      <div
                        className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
                          indicator.enabled
                            ? "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-400"
                            : "border-border bg-muted/50 text-muted-foreground"
                        }`}
                      >
                        <Icon className="h-3 w-3" />
                        {indicator.label}
                      </div>
                    </TooltipTrigger>
                    <TooltipContent>
                      <p>{indicator.enabled ? indicator.enabledText : indicator.disabledText}</p>
                    </TooltipContent>
                  </Tooltip>
                )
              })}

              {/* User ID with copy */}
              <div className="ml-auto hidden items-center gap-1 text-xs text-muted-foreground sm:flex">
                <span className="font-mono">{userId.slice(0, 8)}...</span>
                <CopyButton value={userId} label="user ID" />
              </div>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Account Info + Activity side-by-side */}
      <PageSection delay={0.1}>
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Account Info */}
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <UserIcon className="h-5 w-5 text-muted-foreground" />
                <CardTitle>Account Info</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 text-sm sm:grid-cols-2">
                <div>
                  <p className="text-muted-foreground">Email</p>
                  <div className="flex items-center gap-1">
                    <p>{data.email}</p>
                    <CopyButton value={data.email} label="email" />
                  </div>
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
                  <p className="text-muted-foreground">User ID</p>
                  <div className="flex items-center gap-1">
                    <p className="font-mono text-xs">{userId.slice(0, 8)}...</p>
                    <CopyButton value={userId} label="user ID" />
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Activity */}
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Clock className="h-5 w-5 text-muted-foreground" />
                <CardTitle>Activity</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 text-sm sm:grid-cols-2">
                <div>
                  <p className="text-muted-foreground">Login count</p>
                  <p className="flex items-center gap-1.5 text-xl font-semibold">
                    <LogIn className="h-4 w-4 text-muted-foreground" />
                    {data.loginCount ?? 0}
                  </p>
                </div>
                <TimestampField label="Last login" value={data.joinedAt} icon={Calendar} />
                <TimestampField label="Joined" value={data.joinedAt} icon={Calendar} />
                <TimestampField label="Last updated" value={data.updatedAt} icon={Clock} />
                <TimestampField label="Created" value={data.createdAt} icon={Calendar} />
                {data.verifiedAt && (
                  <TimestampField label="Verified at" value={data.verifiedAt} icon={BadgeCheck} />
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </PageSection>

      <Separator />

      {/* Admin Actions */}
      <PageSection delay={0.15}>
        <SectionHeading
          icon={Shield}
          title="Admin Actions"
          description="Toggle account properties and manage permissions."
        />
        <Card>
          <CardContent className="divide-y pt-6">
            {/* Active toggle */}
            <div className="flex items-center justify-between py-4 first:pt-0 last:pb-0">
              <div className="space-y-0.5">
                <p className="text-sm font-medium">Account active</p>
                <p className="text-xs text-muted-foreground">
                  {data.isActive ? "User can sign in and access the platform." : "User is deactivated and cannot sign in."}
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
                  onCheckedChange={() => setStatusOpen(true)}
                  disabled={updateUser.isPending}
                />
              </div>
            </div>

            {/* Superuser toggle */}
            <div className="flex items-center justify-between py-4 first:pt-0 last:pb-0">
              <div className="space-y-0.5">
                <p className="text-sm font-medium">Superuser privileges</p>
                <p className="text-xs text-muted-foreground">
                  {data.isSuperuser ? "Full administrative access to all resources." : "Standard user privileges."}
                </p>
              </div>
              <div className="flex items-center gap-3">
                {data.isSuperuser && (
                  <Badge variant="destructive">Superuser</Badge>
                )}
                <Switch
                  checked={data.isSuperuser ?? false}
                  onCheckedChange={() => updateUser.mutate({ is_superuser: !data.isSuperuser })}
                  disabled={updateUser.isPending}
                />
              </div>
            </div>

            {/* Verification toggle */}
            <div className="flex items-center justify-between py-4 first:pt-0 last:pb-0">
              <div className="space-y-0.5">
                <p className="text-sm font-medium">Email verified</p>
                <p className="text-xs text-muted-foreground">
                  {data.isVerified ? "Email address has been confirmed." : "Email address is unverified."}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <Badge variant={data.isVerified ? "default" : "outline"}>
                  {data.isVerified ? "Verified" : "Unverified"}
                </Badge>
                <Switch
                  checked={data.isVerified ?? false}
                  onCheckedChange={() => updateUser.mutate({ is_verified: !data.isVerified })}
                  disabled={updateUser.isPending}
                />
              </div>
            </div>

            {/* Role management link */}
            <div className="flex items-center justify-between py-4 first:pt-0 last:pb-0">
              <div className="space-y-0.5">
                <p className="text-sm font-medium">Roles</p>
                <p className="text-xs text-muted-foreground">
                  {roleNames.length > 0 ? `Assigned: ${roleNames.join(", ")}` : "No roles assigned."}
                </p>
              </div>
              <Button variant="outline" size="sm" onClick={() => setRolesOpen(true)}>
                <KeyRound className="mr-2 h-4 w-4" />
                Manage roles
              </Button>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      <Separator />

      {/* Roles */}
      <PageSection delay={0.2}>
        <SectionHeading
          icon={KeyRound}
          title="Roles"
          description="Assigned permission roles for this user."
          actions={
            <Button variant="outline" size="sm" onClick={() => setRolesOpen(true)}>
              Manage roles
            </Button>
          }
        />
        <Card>
          <CardContent className="pt-6">
            {(data.roles ?? []).length === 0 ? (
              <p className="text-sm text-muted-foreground">No roles assigned.</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {(data.roles ?? []).map((role) => (
                  <Badge key={role.roleId} variant="secondary" className="gap-1.5 px-3 py-1.5">
                    <KeyRound className="h-3 w-3" />
                    {role.roleName}
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="ml-1 text-xs text-muted-foreground">
                          (since {formatRelativeTimeShort(role.assignedAt)})
                        </span>
                      </TooltipTrigger>
                      <TooltipContent>
                        Assigned {formatDateTime(role.assignedAt)}
                      </TooltipContent>
                    </Tooltip>
                  </Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </PageSection>

      <Separator />

      {/* Team Memberships */}
      <PageSection delay={0.25}>
        <SectionHeading
          icon={Users}
          title="Teams"
          description={`Member of ${(data.teams ?? []).length} team${(data.teams ?? []).length !== 1 ? "s" : ""}.`}
        />
        <Card>
          <CardContent className="pt-6">
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
                        <Badge variant="outline" className="capitalize">
                          {team.role ?? "member"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {team.isOwner ? (
                          <Badge className="gap-1 bg-amber-100 text-amber-700 hover:bg-amber-100 dark:bg-amber-900/30 dark:text-amber-400">
                            Owner
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground">No</span>
                        )}
                      </TableCell>
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
        <>
          <Separator />
          <PageSection delay={0.3}>
            <SectionHeading
              icon={Link2}
              title="Linked OAuth Accounts"
              description="External identity providers linked to this user."
            />
            <Card>
              <CardContent className="pt-6">
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
                        <TableCell>
                          <div className="flex items-center gap-1">
                            <span className="font-mono text-xs text-muted-foreground">
                              {account.accountId}
                            </span>
                            <CopyButton value={account.accountId} label="account ID" />
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </PageSection>
        </>
      )}

      <Separator />

      {/* Recent Activity Timeline */}
      <PageSection delay={0.35}>
        <UserActivityTimeline userId={userId} />
      </PageSection>

      <Separator />

      {/* Danger Zone */}
      <PageSection delay={0.4}>
        <Card className="border-destructive/30">
          <CardHeader>
            <CardTitle className="text-destructive">Danger Zone</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">Delete this user</p>
                <p className="text-sm text-muted-foreground">
                  Permanently remove <strong>{data.email}</strong> and all associated data. This action cannot be undone.
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
      <EditUserDialog user={data} open={editOpen} onOpenChange={setEditOpen} />
      <ManageRolesDialog userId={userId} userEmail={data.email} open={rolesOpen} onOpenChange={setRolesOpen} />
      <ToggleUserStatusDialog userId={userId} userEmail={data.email} userName={data.name ?? undefined} isActive={data.isActive ?? true} open={statusOpen} onOpenChange={setStatusOpen} />
      <DeleteUserDialog userId={userId} userEmail={data.email} open={deleteOpen} onOpenChange={setDeleteOpen} navigateOnDelete />
    </PageContainer>
  )
}
