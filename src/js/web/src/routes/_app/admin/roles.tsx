import { useQueryClient } from "@tanstack/react-query"
import { createFileRoute, Link } from "@tanstack/react-router"
import type { LucideIcon } from "lucide-react"
import {
  AlertCircle,
  CheckCircle2,
  Clock,
  Download,
  GitBranch,
  Headset,
  Inbox,
  Info,
  LifeBuoy,
  List,
  Loader2,
  Mail,
  MailPlus,
  MapPin,
  Monitor,
  Phone,
  PhoneForwarded,
  Printer,
  Save,
  Shield,
  ShieldAlert,
  TicketCheck,
  Users,
  Voicemail,
  XCircle,
} from "lucide-react"
import { Fragment, useCallback, useEffect, useMemo, useState } from "react"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { DataFreshness } from "@/components/ui/data-freshness"
import { EmptyState } from "@/components/ui/empty-state"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Skeleton, SkeletonCard } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useAdminTeams, useDefaultPermissions, useTeamPermissions, useUpdateDefaultPermissions, useUpdateTeamPermissions } from "@/lib/api/hooks/admin"
import { type CsvHeader, exportToCsv } from "@/lib/csv-export"
import type { DefaultPermissionEntry, DefaultPermissionTemplate, FeatureArea, TeamRolePermission, TeamRolePermissionEntry, TeamRoles } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/admin/roles")({
  component: AdminRolesPage,
})

// -- Constants ---------------------------------------------------------------

interface FeatureAreaNode {
  key: FeatureArea
  label: string
  icon: LucideIcon
  children?: { key: FeatureArea; label: string; icon: LucideIcon }[]
}

const FEATURE_AREAS: readonly FeatureAreaNode[] = [
  { key: "DEVICES", label: "Devices", icon: Monitor },
  {
    key: "VOICE",
    label: "Voice",
    icon: Phone,
    children: [
      { key: "VOICE_PHONE_NUMBERS", label: "Phone Numbers", icon: Phone },
      { key: "VOICE_EXTENSIONS", label: "Extensions", icon: PhoneForwarded },
      { key: "VOICE_VOICEMAIL", label: "Voicemail", icon: Voicemail },
      { key: "VOICE_VOICEMAIL_BOXES", label: "Voicemail Boxes", icon: Inbox },
    ],
  },
  {
    key: "FAX",
    label: "Fax",
    icon: Printer,
    children: [
      { key: "FAX_NUMBERS", label: "Fax Numbers", icon: Printer },
      { key: "FAX_MESSAGES", label: "Fax Messages", icon: Mail },
      { key: "FAX_EMAIL_ROUTES", label: "Email Routes", icon: MailPlus },
    ],
  },
  {
    key: "SUPPORT",
    label: "Support",
    icon: LifeBuoy,
    children: [{ key: "SUPPORT_TICKETS", label: "Tickets", icon: TicketCheck }],
  },
  {
    key: "CALL_ROUTING",
    label: "Call Routing",
    icon: GitBranch,
    children: [
      { key: "CALL_ROUTING_QUEUES", label: "Call Queues", icon: Headset },
      { key: "CALL_ROUTING_RING_GROUPS", label: "Ring Groups", icon: Users },
      { key: "CALL_ROUTING_IVR_MENUS", label: "IVR Menus", icon: List },
      { key: "CALL_ROUTING_TIME_CONDITIONS", label: "Time Conditions", icon: Clock },
    ],
  },
  { key: "E911", label: "E911", icon: ShieldAlert },
  { key: "LOCATIONS", label: "Locations", icon: MapPin },
  { key: "SCHEDULES", label: "Schedules", icon: Clock },
  { key: "TEAMS", label: "Teams", icon: Users },
]

function allFeatureKeys(): FeatureArea[] {
  const keys: FeatureArea[] = []
  for (const area of FEATURE_AREAS) {
    keys.push(area.key)
    if (area.children) {
      for (const child of area.children) keys.push(child.key)
    }
  }
  return keys
}

const ALL_FEATURE_KEYS = allFeatureKeys()

const ROLES: TeamRoles[] = ["ADMIN", "MEMBER"]

interface PermissionExportRow {
  teamName: string
  role: string
  featureArea: string
  canView: string
  canEdit: string
}

const csvHeaders: CsvHeader<PermissionExportRow>[] = [
  { label: "Team", accessor: (r) => r.teamName },
  { label: "Role", accessor: (r) => r.role },
  { label: "Feature Area", accessor: (r) => r.featureArea },
  { label: "Can View", accessor: (r) => r.canView },
  { label: "Can Edit", accessor: (r) => r.canEdit },
]

// -- Helpers -----------------------------------------------------------------

function buildDefaultPermissions(): Record<string, Record<string, { canView: boolean; canEdit: boolean }>> {
  const result: Record<string, Record<string, { canView: boolean; canEdit: boolean }>> = {}
  for (const role of ROLES) {
    result[role] = {}
    for (const key of ALL_FEATURE_KEYS) {
      if (role === "ADMIN") {
        result[role][key] = { canView: true, canEdit: true }
      } else {
        result[role][key] = { canView: true, canEdit: false }
      }
    }
  }
  return result
}

function mergeServerPermissions(rows: TeamRolePermission[]): Record<string, Record<string, { canView: boolean; canEdit: boolean }>> {
  const matrix = buildDefaultPermissions()
  for (const row of rows) {
    if (matrix[row.role] && matrix[row.role][row.featureArea]) {
      matrix[row.role][row.featureArea] = {
        canView: row.canView,
        canEdit: row.canEdit,
      }
    }
  }
  return matrix
}

function matrixToEntries(matrix: Record<string, Record<string, { canView: boolean; canEdit: boolean }>>): TeamRolePermissionEntry[] {
  const entries: TeamRolePermissionEntry[] = []
  for (const role of ROLES) {
    for (const key of ALL_FEATURE_KEYS) {
      const perm = matrix[role]?.[key]
      if (perm) {
        entries.push({
          role: role as TeamRoles,
          featureArea: key,
          canView: perm.canView,
          canEdit: perm.canEdit,
        })
      }
    }
  }
  return entries
}

function mergeDefaultTemplatePermissions(rows: DefaultPermissionTemplate[]): Record<string, Record<string, { canView: boolean; canEdit: boolean }>> {
  const matrix = buildDefaultPermissions()
  for (const row of rows) {
    if (matrix[row.role] && matrix[row.role][row.featureArea]) {
      matrix[row.role][row.featureArea] = {
        canView: row.canView,
        canEdit: row.canEdit,
      }
    }
  }
  return matrix
}

function matrixToDefaultEntries(matrix: Record<string, Record<string, { canView: boolean; canEdit: boolean }>>): DefaultPermissionEntry[] {
  const entries: DefaultPermissionEntry[] = []
  for (const role of ROLES) {
    for (const key of ALL_FEATURE_KEYS) {
      const perm = matrix[role]?.[key]
      if (perm) {
        entries.push({
          role: role as TeamRoles,
          featureArea: key,
          canView: perm.canView,
          canEdit: perm.canEdit,
        })
      }
    }
  }
  return entries
}

function countPermissions(matrix: Record<string, Record<string, { canView: boolean; canEdit: boolean }>>): { allowed: number; total: number } {
  let allowed = 0
  let total = 0
  for (const role of ROLES) {
    for (const key of ALL_FEATURE_KEYS) {
      const perm = matrix[role]?.[key]
      if (perm) {
        if (perm.canView) allowed++
        if (perm.canEdit) allowed++
        total += 2
      }
    }
  }
  return { allowed, total }
}

// -- Main page ---------------------------------------------------------------

function AdminRolesPage() {
  useDocumentTitle("Roles & Permissions")

  const queryClient = useQueryClient()
  const { data, isLoading, isError, refetch, dataUpdatedAt, isRefetching } = useAdminTeams({
    page: 1,
    pageSize: 100,
  })

  const teams = data?.items ?? []

  const handleExportAll = useCallback(() => {
    if (!teams.length) return
    const rows: PermissionExportRow[] = []
    for (const team of teams) {
      const cached = queryClient.getQueryData<TeamRolePermission[]>(["team-permissions", team.id])
      const matrix = cached ? mergeServerPermissions(cached) : buildDefaultPermissions()
      for (const role of ROLES) {
        for (const area of FEATURE_AREAS) {
          if (area.children) {
            for (const child of area.children) {
              const perm = matrix[role]?.[child.key] ?? { canView: false, canEdit: false }
              rows.push({
                teamName: team.name,
                role,
                featureArea: `${area.label} > ${child.label}`,
                canView: perm.canView ? "Yes" : "No",
                canEdit: perm.canEdit ? "Yes" : "No",
              })
            }
          } else {
            const perm = matrix[role]?.[area.key] ?? { canView: false, canEdit: false }
            rows.push({
              teamName: team.name,
              role,
              featureArea: area.label,
              canView: perm.canView ? "Yes" : "No",
              canEdit: perm.canEdit ? "Yes" : "No",
            })
          }
        }
      }
    }
    exportToCsv("role-permissions", csvHeaders, rows)
  }, [teams, queryClient])

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Roles & Permissions"
        description="Configure feature-level permissions for team roles across the system."
        breadcrumbs={<AdminBreadcrumbs />}
        actions={
          <div className="flex items-center gap-2">
            <DataFreshness dataUpdatedAt={dataUpdatedAt} onRefresh={() => refetch()} isRefreshing={isRefetching} />
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!teams.length}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
          </div>
        }
      />
      <AdminNav />

      {/* Overview */}
      <PageSection>
        <SectionErrorBoundary name="Permissions Overview">
          <div className="flex items-start gap-2 rounded-md border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-800 dark:border-blue-900 dark:bg-blue-950 dark:text-blue-200">
            <Info className="mt-0.5 h-4 w-4 shrink-0" />
            <div>
              <p className="font-medium">How permissions work</p>
              <p className="mt-1 text-xs">
                Each team has its own permission matrix that controls what <strong>ADMIN</strong> and <strong>MEMBER</strong> roles can access. Permissions are checked per feature
                area (Devices, Voice, Fax, etc.) with separate View and Edit grants. Superusers bypass all permission checks.
              </p>
            </div>
          </div>
        </SectionErrorBoundary>
      </PageSection>

      {/* Team permission cards */}
      <PageSection delay={0.1}>
        {isLoading ? (
          <div className="space-y-4">
            <SkeletonCard />
            <SkeletonCard />
          </div>
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load teams"
            description="Something went wrong while fetching team data."
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Refresh
              </Button>
            }
          />
        ) : teams.length === 0 ? (
          <EmptyState icon={Shield} title="No teams found" description="Create a team first to configure role permissions." />
        ) : (
          <div className="space-y-6">
            {teams.map((team) => (
              <SectionErrorBoundary key={team.id} name={`${team.name} permissions`}>
                <TeamPermissionCard teamId={team.id} teamName={team.name} memberCount={team.memberCount} />
              </SectionErrorBoundary>
            ))}
          </div>
        )}
      </PageSection>

      {/* Default permissions template */}
      <PageSection delay={0.2}>
        <SectionErrorBoundary name="Default Permissions Template">
          <DefaultPermissionsCard />
        </SectionErrorBoundary>
      </PageSection>
    </PageContainer>
  )
}

// -- Per-team permission card ------------------------------------------------

function TeamPermissionCard({ teamId, teamName, memberCount }: { teamId: string; teamName: string; memberCount?: number }) {
  const [isEditing, setIsEditing] = useState(false)

  const { data: serverPermissions, isLoading, isRefetching } = useTeamPermissions(teamId)

  const serverMatrix = useMemo(() => {
    if (!serverPermissions) return buildDefaultPermissions()
    return mergeServerPermissions(serverPermissions)
  }, [serverPermissions])

  const [editMatrix, setEditMatrix] = useState(serverMatrix)
  const [initialized, setInitialized] = useState(false)

  // Seed edit state from server when loaded
  useEffect(() => {
    if (serverPermissions && !initialized) {
      setEditMatrix(mergeServerPermissions(serverPermissions))
      setInitialized(true)
    }
  }, [serverPermissions, initialized])

  // Re-sync when server permissions change and not editing
  useEffect(() => {
    if (!isEditing && serverPermissions) {
      setEditMatrix(mergeServerPermissions(serverPermissions))
    }
  }, [serverPermissions, isEditing])

  const currentMatrix = isEditing ? editMatrix : serverMatrix
  const { allowed, total } = countPermissions(currentMatrix)

  const togglePermission = useCallback((role: string, featureArea: string, field: "canView" | "canEdit") => {
    setEditMatrix((prev) => {
      const next = { ...prev }
      next[role] = { ...next[role] }
      next[role][featureArea] = { ...next[role][featureArea] }
      const current = next[role][featureArea][field]
      next[role][featureArea][field] = !current
      if (field === "canView" && current) {
        next[role][featureArea].canEdit = false
      }
      if (field === "canEdit" && !current) {
        next[role][featureArea].canView = true
      }
      return next
    })
  }, [])

  const toggleParent = useCallback((role: string, children: { key: FeatureArea }[], field: "canView" | "canEdit") => {
    setEditMatrix((prev) => {
      const next = { ...prev }
      next[role] = { ...next[role] }
      const allSet = children.every((c) => next[role][c.key]?.[field])
      const newValue = !allSet
      for (const child of children) {
        next[role][child.key] = { ...next[role][child.key] }
        next[role][child.key][field] = newValue
        if (field === "canView" && !newValue) {
          next[role][child.key].canEdit = false
        }
        if (field === "canEdit" && newValue) {
          next[role][child.key].canView = true
        }
      }
      return next
    })
  }, [])

  const updatePermissions = useUpdateTeamPermissions(teamId)

  const handleSave = useCallback(() => {
    const entries = matrixToEntries(editMatrix)
    updatePermissions.mutate(entries, {
      onSuccess: () => {
        setIsEditing(false)
      },
    })
  }, [editMatrix, updatePermissions])

  const handleCancel = useCallback(() => {
    setEditMatrix(serverMatrix)
    setIsEditing(false)
  }, [serverMatrix])

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary/10 text-primary">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <CardTitle className="text-base">
                <Link to="/admin/teams/$teamId" params={{ teamId }} className="hover:underline">
                  {teamName}
                </Link>
              </CardTitle>
              <p className="text-xs text-muted-foreground">
                {memberCount ?? 0} member{(memberCount ?? 0) !== 1 ? "s" : ""} &middot; {allowed}/{total} permissions granted
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {isEditing ? (
              <>
                <Button variant="outline" size="sm" onClick={handleCancel} disabled={updatePermissions.isPending}>
                  Cancel
                </Button>
                <Button size="sm" onClick={() => handleSave()} disabled={updatePermissions.isPending}>
                  {updatePermissions.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
                  Save
                </Button>
              </>
            ) : (
              <Button variant="outline" size="sm" onClick={() => setIsEditing(true)}>
                Edit
              </Button>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="overflow-x-auto rounded-md border">
            <Table aria-label="Loading permissions">
              <TableHeader>
                <TableRow>
                  <TableHead>
                    <Skeleton className="h-4 w-24" />
                  </TableHead>
                  {ROLES.map((role) => (
                    <Fragment key={`skel-hdr-${role}`}>
                      <TableHead className="w-[100px] text-center">
                        <Skeleton className="mx-auto h-4 w-14" />
                      </TableHead>
                      <TableHead className="w-[100px] text-center">
                        <Skeleton className="mx-auto h-4 w-14" />
                      </TableHead>
                    </Fragment>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {Array.from({ length: 5 }).map((_, i) => (
                  // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
                  <TableRow key={`skel-row-${i}`}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Skeleton className="h-4 w-4 rounded" />
                        <Skeleton className="h-4 w-20" />
                      </div>
                    </TableCell>
                    {ROLES.map((role) => (
                      // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders with stable role key
                      <Fragment key={`skel-cell-${role}-${i}`}>
                        <TableCell className="text-center">
                          <Skeleton className="mx-auto h-4 w-4 rounded" />
                        </TableCell>
                        <TableCell className="text-center">
                          <Skeleton className="mx-auto h-4 w-4 rounded" />
                        </TableCell>
                      </Fragment>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-md border">
            <Table aria-label="Role permissions matrix" aria-busy={isLoading || isRefetching}>
              <TableHeader className="sticky top-0 z-10 bg-background">
                <TableRow>
                  <TableHead>Feature Area</TableHead>
                  {ROLES.map((role) => (
                    <Fragment key={role}>
                      <TableHead className="w-[100px] text-center">
                        <div className="text-xs leading-tight">
                          <div className="font-semibold">{role}</div>
                          <div className="flex items-center justify-center gap-1 font-normal text-muted-foreground">
                            View
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Info className="h-3 w-3 shrink-0 cursor-help" />
                              </TooltipTrigger>
                              <TooltipContent>Allows reading and listing resources in this category</TooltipContent>
                            </Tooltip>
                          </div>
                        </div>
                      </TableHead>
                      <TableHead className="w-[100px] text-center">
                        <div className="text-xs leading-tight">
                          <div className="font-semibold">{role}</div>
                          <div className="flex items-center justify-center gap-1 font-normal text-muted-foreground">
                            Edit
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Info className="h-3 w-3 shrink-0 cursor-help" />
                              </TooltipTrigger>
                              <TooltipContent>Allows creating, updating, and deleting. Automatically includes View access</TooltipContent>
                            </Tooltip>
                          </div>
                        </div>
                      </TableHead>
                    </Fragment>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {FEATURE_AREAS.map((area) => (
                  <Fragment key={area.key}>
                    <TableRow className={`hover:bg-muted/50 ${area.children ? "bg-muted/20" : ""}`}>
                      <TableCell className="text-sm font-medium">
                        <div className="flex items-center gap-2">
                          <area.icon className="h-4 w-4 text-muted-foreground" />
                          {area.label}
                        </div>
                      </TableCell>
                      {ROLES.map((role) => {
                        if (area.children) {
                          const allView = area.children.every((c) => currentMatrix[role]?.[c.key]?.canView)
                          const noneView = area.children.every((c) => !currentMatrix[role]?.[c.key]?.canView)
                          const allEdit = area.children.every((c) => currentMatrix[role]?.[c.key]?.canEdit)
                          const noneEdit = area.children.every((c) => !currentMatrix[role]?.[c.key]?.canEdit)
                          return (
                            <Fragment key={role}>
                              <TableCell className="text-center">
                                {isEditing ? (
                                  <div className="flex justify-center">
                                    <Checkbox
                                      checked={allView}
                                      indeterminate={!allView && !noneView}
                                      onChange={() => toggleParent(role, area.children!, "canView")}
                                      disabled={updatePermissions.isPending}
                                      aria-label={`${role} can view all ${area.label}`}
                                    />
                                  </div>
                                ) : (
                                  <PermissionIndicator allowed={allView} />
                                )}
                              </TableCell>
                              <TableCell className="text-center">
                                {isEditing ? (
                                  <div className="flex justify-center">
                                    <Checkbox
                                      checked={allEdit}
                                      indeterminate={!allEdit && !noneEdit}
                                      onChange={() => toggleParent(role, area.children!, "canEdit")}
                                      disabled={updatePermissions.isPending}
                                      aria-label={`${role} can edit all ${area.label}`}
                                    />
                                  </div>
                                ) : (
                                  <PermissionIndicator allowed={allEdit} />
                                )}
                              </TableCell>
                            </Fragment>
                          )
                        }
                        const perm = currentMatrix[role]?.[area.key] ?? { canView: false, canEdit: false }
                        return (
                          <Fragment key={role}>
                            <TableCell className="text-center">
                              {isEditing ? (
                                <div className="flex justify-center">
                                  <Checkbox
                                    checked={perm.canView}
                                    onChange={() => togglePermission(role, area.key, "canView")}
                                    disabled={updatePermissions.isPending}
                                    aria-label={`${role} can view ${area.label}`}
                                  />
                                </div>
                              ) : (
                                <PermissionIndicator allowed={perm.canView} />
                              )}
                            </TableCell>
                            <TableCell className="text-center">
                              {isEditing ? (
                                <div className="flex justify-center">
                                  <Checkbox
                                    checked={perm.canEdit}
                                    onChange={() => togglePermission(role, area.key, "canEdit")}
                                    disabled={updatePermissions.isPending}
                                    aria-label={`${role} can edit ${area.label}`}
                                  />
                                </div>
                              ) : (
                                <PermissionIndicator allowed={perm.canEdit} />
                              )}
                            </TableCell>
                          </Fragment>
                        )
                      })}
                    </TableRow>
                    {area.children?.map((child) => (
                      <TableRow key={child.key} className="hover:bg-muted/50">
                        <TableCell className="text-sm text-muted-foreground">
                          <div className="flex items-center gap-2 pl-6">
                            <child.icon className="h-3.5 w-3.5" />
                            {child.label}
                          </div>
                        </TableCell>
                        {ROLES.map((role) => {
                          const perm = currentMatrix[role]?.[child.key] ?? { canView: false, canEdit: false }
                          return (
                            <Fragment key={role}>
                              <TableCell className="text-center">
                                {isEditing ? (
                                  <div className="flex justify-center">
                                    <Checkbox
                                      checked={perm.canView}
                                      onChange={() => togglePermission(role, child.key, "canView")}
                                      disabled={updatePermissions.isPending}
                                      aria-label={`${role} can view ${child.label}`}
                                    />
                                  </div>
                                ) : (
                                  <PermissionIndicator allowed={perm.canView} />
                                )}
                              </TableCell>
                              <TableCell className="text-center">
                                {isEditing ? (
                                  <div className="flex justify-center">
                                    <Checkbox
                                      checked={perm.canEdit}
                                      onChange={() => togglePermission(role, child.key, "canEdit")}
                                      disabled={updatePermissions.isPending}
                                      aria-label={`${role} can edit ${child.label}`}
                                    />
                                  </div>
                                ) : (
                                  <PermissionIndicator allowed={perm.canEdit} />
                                )}
                              </TableCell>
                            </Fragment>
                          )
                        })}
                      </TableRow>
                    ))}
                  </Fragment>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// -- Default permissions template card ----------------------------------------

function DefaultPermissionsCard() {
  const [isEditing, setIsEditing] = useState(false)

  const { data: serverDefaults, isLoading, isRefetching } = useDefaultPermissions()

  const hasCustomDefaults = (serverDefaults?.length ?? 0) > 0

  const serverMatrix = useMemo(() => {
    if (!serverDefaults || serverDefaults.length === 0) return buildDefaultPermissions()
    return mergeDefaultTemplatePermissions(serverDefaults)
  }, [serverDefaults])

  const [editMatrix, setEditMatrix] = useState(serverMatrix)
  const [initialized, setInitialized] = useState(false)

  // Seed edit state from server when loaded
  useEffect(() => {
    if (serverDefaults && !initialized) {
      setEditMatrix(hasCustomDefaults ? mergeDefaultTemplatePermissions(serverDefaults) : buildDefaultPermissions())
      setInitialized(true)
    }
  }, [serverDefaults, initialized, hasCustomDefaults])

  // Re-sync when server data changes and not editing
  useEffect(() => {
    if (!isEditing && serverDefaults) {
      setEditMatrix(hasCustomDefaults ? mergeDefaultTemplatePermissions(serverDefaults) : buildDefaultPermissions())
    }
  }, [serverDefaults, isEditing, hasCustomDefaults])

  const currentMatrix = isEditing ? editMatrix : serverMatrix

  const togglePermission = useCallback((role: string, featureArea: string, field: "canView" | "canEdit") => {
    setEditMatrix((prev) => {
      const next = { ...prev }
      next[role] = { ...next[role] }
      next[role][featureArea] = { ...next[role][featureArea] }
      const current = next[role][featureArea][field]
      next[role][featureArea][field] = !current
      if (field === "canView" && current) {
        next[role][featureArea].canEdit = false
      }
      if (field === "canEdit" && !current) {
        next[role][featureArea].canView = true
      }
      return next
    })
  }, [])

  const toggleParent = useCallback((role: string, children: { key: FeatureArea }[], field: "canView" | "canEdit") => {
    setEditMatrix((prev) => {
      const next = { ...prev }
      next[role] = { ...next[role] }
      const allSet = children.every((c) => next[role][c.key]?.[field])
      const newValue = !allSet
      for (const child of children) {
        next[role][child.key] = { ...next[role][child.key] }
        next[role][child.key][field] = newValue
        if (field === "canView" && !newValue) {
          next[role][child.key].canEdit = false
        }
        if (field === "canEdit" && newValue) {
          next[role][child.key].canView = true
        }
      }
      return next
    })
  }, [])

  const updateDefaults = useUpdateDefaultPermissions()

  const handleSave = useCallback(() => {
    const entries = matrixToDefaultEntries(editMatrix)
    updateDefaults.mutate(entries, {
      onSuccess: () => {
        setIsEditing(false)
      },
    })
  }, [editMatrix, updateDefaults])

  const handleCancel = useCallback(() => {
    setEditMatrix(serverMatrix)
    setIsEditing(false)
  }, [serverMatrix])

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary/10 text-primary">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <CardTitle className="text-base">Default Permissions Template</CardTitle>
              <CardDescription>
                {hasCustomDefaults
                  ? "Custom default permissions are applied when new teams are created."
                  : "Using system defaults (Admin=full access, Member=view only). Edit to customize."}
              </CardDescription>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {isEditing ? (
              <>
                <Button variant="outline" size="sm" onClick={handleCancel} disabled={updateDefaults.isPending}>
                  Cancel
                </Button>
                <Button size="sm" onClick={handleSave} disabled={updateDefaults.isPending}>
                  {updateDefaults.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
                  Save
                </Button>
              </>
            ) : (
              <Button variant="outline" size="sm" onClick={() => setIsEditing(true)}>
                Edit
              </Button>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="overflow-x-auto rounded-md border">
            <Table aria-label="Loading default permissions">
              <TableHeader>
                <TableRow>
                  <TableHead>
                    <Skeleton className="h-4 w-24" />
                  </TableHead>
                  <TableHead className="w-[100px] text-center">
                    <Skeleton className="mx-auto h-4 w-14" />
                  </TableHead>
                  {ROLES.map((role) => (
                    <Fragment key={`skel-hdr-${role}`}>
                      <TableHead className="w-[100px] text-center">
                        <Skeleton className="mx-auto h-4 w-14" />
                      </TableHead>
                      <TableHead className="w-[100px] text-center">
                        <Skeleton className="mx-auto h-4 w-14" />
                      </TableHead>
                    </Fragment>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {Array.from({ length: 5 }).map((_, i) => (
                  // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
                  <TableRow key={`skel-row-default-${i}`}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Skeleton className="h-4 w-4 rounded" />
                        <Skeleton className="h-4 w-20" />
                      </div>
                    </TableCell>
                    <TableCell className="text-center">
                      <Skeleton className="mx-auto h-4 w-4 rounded" />
                    </TableCell>
                    {ROLES.map((role) => (
                      // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders with stable role key
                      <Fragment key={`skel-cell-default-${role}-${i}`}>
                        <TableCell className="text-center">
                          <Skeleton className="mx-auto h-4 w-4 rounded" />
                        </TableCell>
                        <TableCell className="text-center">
                          <Skeleton className="mx-auto h-4 w-4 rounded" />
                        </TableCell>
                      </Fragment>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-md border">
            <Table aria-label="Default permissions template" aria-busy={isLoading || isRefetching}>
              <TableHeader className="sticky top-0 z-10 bg-background">
                <TableRow>
                  <TableHead>Feature Area</TableHead>
                  <TableHead className="w-[100px] text-center">
                    <div className="text-xs leading-tight">
                      <div className="font-semibold">SUPERUSER</div>
                      <div className="font-normal text-muted-foreground">Full Access</div>
                    </div>
                  </TableHead>
                  {ROLES.map((role) => (
                    <Fragment key={role}>
                      <TableHead className="w-[100px] text-center">
                        <div className="text-xs leading-tight">
                          <div className="font-semibold">{role}</div>
                          <div className="flex items-center justify-center gap-1 font-normal text-muted-foreground">
                            View
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Info className="h-3 w-3 shrink-0 cursor-help" />
                              </TooltipTrigger>
                              <TooltipContent>Allows reading and listing resources in this category</TooltipContent>
                            </Tooltip>
                          </div>
                        </div>
                      </TableHead>
                      <TableHead className="w-[100px] text-center">
                        <div className="text-xs leading-tight">
                          <div className="font-semibold">{role}</div>
                          <div className="flex items-center justify-center gap-1 font-normal text-muted-foreground">
                            Edit
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Info className="h-3 w-3 shrink-0 cursor-help" />
                              </TooltipTrigger>
                              <TooltipContent>Allows creating, updating, and deleting. Automatically includes View access</TooltipContent>
                            </Tooltip>
                          </div>
                        </div>
                      </TableHead>
                    </Fragment>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {FEATURE_AREAS.map((area) => (
                  <Fragment key={area.key}>
                    <TableRow className={`hover:bg-muted/50 ${area.children ? "bg-muted/20" : ""}`}>
                      <TableCell className="text-sm font-medium">
                        <div className="flex items-center gap-2">
                          <area.icon className="h-4 w-4 text-muted-foreground" />
                          {area.label}
                        </div>
                      </TableCell>
                      {/* Superuser column - always full access */}
                      <TableCell className="text-center">
                        <PermissionIndicator allowed={true} />
                      </TableCell>
                      {ROLES.map((role) => {
                        if (area.children) {
                          const allView = area.children.every((c) => currentMatrix[role]?.[c.key]?.canView)
                          const noneView = area.children.every((c) => !currentMatrix[role]?.[c.key]?.canView)
                          const allEdit = area.children.every((c) => currentMatrix[role]?.[c.key]?.canEdit)
                          const noneEdit = area.children.every((c) => !currentMatrix[role]?.[c.key]?.canEdit)
                          return (
                            <Fragment key={role}>
                              <TableCell className="text-center">
                                {isEditing ? (
                                  <div className="flex justify-center">
                                    <Checkbox
                                      checked={allView}
                                      indeterminate={!allView && !noneView}
                                      onChange={() => toggleParent(role, area.children!, "canView")}
                                      disabled={updateDefaults.isPending}
                                      aria-label={`${role} can view all ${area.label}`}
                                    />
                                  </div>
                                ) : (
                                  <PermissionIndicator allowed={allView} />
                                )}
                              </TableCell>
                              <TableCell className="text-center">
                                {isEditing ? (
                                  <div className="flex justify-center">
                                    <Checkbox
                                      checked={allEdit}
                                      indeterminate={!allEdit && !noneEdit}
                                      onChange={() => toggleParent(role, area.children!, "canEdit")}
                                      disabled={updateDefaults.isPending}
                                      aria-label={`${role} can edit all ${area.label}`}
                                    />
                                  </div>
                                ) : (
                                  <PermissionIndicator allowed={allEdit} />
                                )}
                              </TableCell>
                            </Fragment>
                          )
                        }
                        const perm = currentMatrix[role]?.[area.key] ?? { canView: false, canEdit: false }
                        return (
                          <Fragment key={role}>
                            <TableCell className="text-center">
                              {isEditing ? (
                                <div className="flex justify-center">
                                  <Checkbox
                                    checked={perm.canView}
                                    onChange={() => togglePermission(role, area.key, "canView")}
                                    disabled={updateDefaults.isPending}
                                    aria-label={`${role} can view ${area.label}`}
                                  />
                                </div>
                              ) : (
                                <PermissionIndicator allowed={perm.canView} />
                              )}
                            </TableCell>
                            <TableCell className="text-center">
                              {isEditing ? (
                                <div className="flex justify-center">
                                  <Checkbox
                                    checked={perm.canEdit}
                                    onChange={() => togglePermission(role, area.key, "canEdit")}
                                    disabled={updateDefaults.isPending}
                                    aria-label={`${role} can edit ${area.label}`}
                                  />
                                </div>
                              ) : (
                                <PermissionIndicator allowed={perm.canEdit} />
                              )}
                            </TableCell>
                          </Fragment>
                        )
                      })}
                    </TableRow>
                    {area.children?.map((child) => (
                      <TableRow key={child.key} className="hover:bg-muted/50">
                        <TableCell className="text-sm text-muted-foreground">
                          <div className="flex items-center gap-2 pl-6">
                            <child.icon className="h-3.5 w-3.5" />
                            {child.label}
                          </div>
                        </TableCell>
                        {/* Superuser column - always full access */}
                        <TableCell className="text-center">
                          <PermissionIndicator allowed={true} />
                        </TableCell>
                        {ROLES.map((role) => {
                          const perm = currentMatrix[role]?.[child.key] ?? { canView: false, canEdit: false }
                          return (
                            <Fragment key={role}>
                              <TableCell className="text-center">
                                {isEditing ? (
                                  <div className="flex justify-center">
                                    <Checkbox
                                      checked={perm.canView}
                                      onChange={() => togglePermission(role, child.key, "canView")}
                                      disabled={updateDefaults.isPending}
                                      aria-label={`${role} can view ${child.label}`}
                                    />
                                  </div>
                                ) : (
                                  <PermissionIndicator allowed={perm.canView} />
                                )}
                              </TableCell>
                              <TableCell className="text-center">
                                {isEditing ? (
                                  <div className="flex justify-center">
                                    <Checkbox
                                      checked={perm.canEdit}
                                      onChange={() => togglePermission(role, child.key, "canEdit")}
                                      disabled={updateDefaults.isPending}
                                      aria-label={`${role} can edit ${child.label}`}
                                    />
                                  </div>
                                ) : (
                                  <PermissionIndicator allowed={perm.canEdit} />
                                )}
                              </TableCell>
                            </Fragment>
                          )
                        })}
                      </TableRow>
                    ))}
                  </Fragment>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// -- Shared components -------------------------------------------------------

function PermissionIndicator({ allowed }: { allowed: boolean }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex items-center justify-center">
          {allowed ? <CheckCircle2 className="h-4 w-4 text-green-500" /> : <XCircle className="h-4 w-4 text-muted-foreground/40" />}
        </span>
      </TooltipTrigger>
      <TooltipContent>{allowed ? "Allowed" : "Not allowed"}</TooltipContent>
    </Tooltip>
  )
}
