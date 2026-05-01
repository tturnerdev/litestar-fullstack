import { createFileRoute, Link } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  AlertCircle,
  BarChart3,
  Cable,
  CheckCircle2,
  Clock,
  CreditCard,
  Download,
  GitBranch,
  Info,
  LifeBuoy,
  Loader2,
  MapPin,
  Monitor,
  Phone,
  Printer,
  Save,
  Shield,
  ShieldAlert,
  XCircle,
} from "lucide-react"
import type { LucideIcon } from "lucide-react"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { EmptyState } from "@/components/ui/empty-state"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useAdminTeams } from "@/lib/api/hooks/admin"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import {
  listTeamPermissions,
  updateTeamPermissions,
  type FeatureArea,
  type TeamRolePermission,
  type TeamRolePermissionEntry,
  type TeamRoles,
} from "@/lib/generated/api"

export const Route = createFileRoute("/_app/admin/roles")({
  component: AdminRolesPage,
})

// -- Constants ---------------------------------------------------------------

const FEATURE_AREAS: readonly { key: FeatureArea; label: string; icon: LucideIcon }[] = [
  { key: "DEVICES", label: "Devices", icon: Monitor },
  { key: "VOICE", label: "Voice", icon: Phone },
  { key: "FAX", label: "Fax", icon: Printer },
  { key: "SUPPORT", label: "Support", icon: LifeBuoy },
  { key: "CALL_ROUTING", label: "Call Routing", icon: GitBranch },
  { key: "CONNECTIONS", label: "Connections", icon: Cable },
  { key: "E911", label: "E911", icon: ShieldAlert },
  { key: "LOCATIONS", label: "Locations", icon: MapPin },
  { key: "SCHEDULES", label: "Schedules", icon: Clock },
  { key: "ORGANIZATION", label: "Organization", icon: CreditCard },
  { key: "TEAMS", label: "Teams", icon: BarChart3 },
]

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
    for (const area of FEATURE_AREAS) {
      if (role === "ADMIN") {
        result[role][area.key] = { canView: true, canEdit: true }
      } else {
        result[role][area.key] = { canView: true, canEdit: false }
      }
    }
  }
  return result
}

function mergeServerPermissions(
  rows: TeamRolePermission[],
): Record<string, Record<string, { canView: boolean; canEdit: boolean }>> {
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

function matrixToEntries(
  matrix: Record<string, Record<string, { canView: boolean; canEdit: boolean }>>,
): TeamRolePermissionEntry[] {
  const entries: TeamRolePermissionEntry[] = []
  for (const role of ROLES) {
    for (const area of FEATURE_AREAS) {
      const perm = matrix[role]?.[area.key]
      if (perm) {
        entries.push({
          role: role as TeamRoles,
          featureArea: area.key,
          canView: perm.canView,
          canEdit: perm.canEdit,
        })
      }
    }
  }
  return entries
}

function countPermissions(
  matrix: Record<string, Record<string, { canView: boolean; canEdit: boolean }>>,
): { allowed: number; total: number } {
  let allowed = 0
  let total = 0
  for (const role of ROLES) {
    for (const area of FEATURE_AREAS) {
      const perm = matrix[role]?.[area.key]
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
  const { data, isLoading, isError, refetch } = useAdminTeams({
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
          <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!teams.length}>
            <Download className="mr-2 h-4 w-4" />
            Export
          </Button>
        }
      />
      <AdminNav />

      {/* Overview */}
      <PageSection>
        <div className="flex items-start gap-2 rounded-md border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-800 dark:border-blue-900 dark:bg-blue-950 dark:text-blue-200">
          <Info className="mt-0.5 h-4 w-4 shrink-0" />
          <div>
            <p className="font-medium">How permissions work</p>
            <p className="mt-1 text-xs">
              Each team has its own permission matrix that controls what <strong>ADMIN</strong> and{" "}
              <strong>MEMBER</strong> roles can access. Permissions are checked per feature area (Devices,
              Voice, Fax, etc.) with separate View and Edit grants. Superusers bypass all permission checks.
            </p>
          </div>
        </div>
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
          <EmptyState
            icon={Shield}
            title="No teams found"
            description="Create a team first to configure role permissions."
          />
        ) : (
          <div className="space-y-6">
            {teams.map((team) => (
              <TeamPermissionCard
                key={team.id}
                teamId={team.id}
                teamName={team.name}
                memberCount={team.memberCount}
              />
            ))}
          </div>
        )}
      </PageSection>
    </PageContainer>
  )
}

// -- Per-team permission card ------------------------------------------------

function TeamPermissionCard({
  teamId,
  teamName,
  memberCount,
}: {
  teamId: string
  teamName: string
  memberCount?: number
}) {
  const queryClient = useQueryClient()
  const [isEditing, setIsEditing] = useState(false)

  const { data: serverPermissions, isLoading } = useQuery({
    queryKey: ["team-permissions", teamId],
    queryFn: async () => {
      const response = await listTeamPermissions({
        path: { team_id: teamId },
      })
      return response.data as TeamRolePermission[]
    },
  })

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

  const togglePermission = useCallback(
    (role: string, featureArea: string, field: "canView" | "canEdit") => {
      setEditMatrix((prev) => {
        const next = { ...prev }
        next[role] = { ...next[role] }
        next[role][featureArea] = { ...next[role][featureArea] }
        const current = next[role][featureArea][field]
        next[role][featureArea][field] = !current
        // Disabling view also disables edit
        if (field === "canView" && current) {
          next[role][featureArea].canEdit = false
        }
        // Enabling edit also enables view
        if (field === "canEdit" && !current) {
          next[role][featureArea].canView = true
        }
        return next
      })
    },
    [],
  )

  const saveMutation = useMutation({
    mutationFn: async () => {
      const entries = matrixToEntries(editMatrix)
      const response = await updateTeamPermissions({
        path: { team_id: teamId },
        body: { permissions: entries },
      })
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["team-permissions", teamId] })
      toast.success(`Permissions updated for ${teamName}`)
      setIsEditing(false)
    },
    onError: (error) => {
      toast.error("Failed to update permissions", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })

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
                <Link
                  to="/admin/teams/$teamId"
                  params={{ teamId }}
                  className="hover:underline"
                >
                  {teamName}
                </Link>
              </CardTitle>
              <p className="text-xs text-muted-foreground">
                {memberCount ?? 0} member{(memberCount ?? 0) !== 1 ? "s" : ""} &middot;{" "}
                {allowed}/{total} permissions granted
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {isEditing ? (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleCancel}
                  disabled={saveMutation.isPending}
                >
                  Cancel
                </Button>
                <Button
                  size="sm"
                  onClick={() => saveMutation.mutate()}
                  disabled={saveMutation.isPending}
                >
                  {saveMutation.isPending ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <Save className="mr-2 h-4 w-4" />
                  )}
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
          <div className="flex items-center justify-center py-6">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
          </div>
        ) : (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Feature Area</TableHead>
                  {ROLES.map((role) => (
                    <TableHead key={`${role}-view`} className="w-[100px] text-center">
                      <div className="text-xs leading-tight">
                        <div className="font-semibold">{role}</div>
                        <div className="font-normal text-muted-foreground">View</div>
                      </div>
                    </TableHead>
                  ))}
                  {ROLES.map((role) => (
                    <TableHead key={`${role}-edit`} className="w-[100px] text-center">
                      <div className="text-xs leading-tight">
                        <div className="font-semibold">{role}</div>
                        <div className="font-normal text-muted-foreground">Edit</div>
                      </div>
                    </TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {FEATURE_AREAS.map((area) => (
                  <TableRow key={area.key} className="hover:bg-muted/50">
                    <TableCell className="text-sm">
                      <div className="flex items-center gap-2">
                        <area.icon className="h-4 w-4 text-muted-foreground" />
                        {area.label}
                      </div>
                    </TableCell>
                    {ROLES.map((role) => {
                      const perm = currentMatrix[role]?.[area.key] ?? { canView: false, canEdit: false }
                      return (
                        <TableCell key={`${role}-view`} className="text-center">
                          {isEditing ? (
                            <div className="flex justify-center">
                              <Checkbox
                                checked={perm.canView}
                                onChange={() => togglePermission(role, area.key, "canView")}
                                disabled={saveMutation.isPending}
                                aria-label={`${role} can view ${area.label}`}
                              />
                            </div>
                          ) : (
                            <PermissionIndicator allowed={perm.canView} />
                          )}
                        </TableCell>
                      )
                    })}
                    {ROLES.map((role) => {
                      const perm = currentMatrix[role]?.[area.key] ?? { canView: false, canEdit: false }
                      return (
                        <TableCell key={`${role}-edit`} className="text-center">
                          {isEditing ? (
                            <div className="flex justify-center">
                              <Checkbox
                                checked={perm.canEdit}
                                onChange={() => togglePermission(role, area.key, "canEdit")}
                                disabled={saveMutation.isPending}
                                aria-label={`${role} can edit ${area.label}`}
                              />
                            </div>
                          ) : (
                            <PermissionIndicator allowed={perm.canEdit} />
                          )}
                        </TableCell>
                      )
                    })}
                  </TableRow>
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
          {allowed ? (
            <CheckCircle2 className="h-4 w-4 text-green-500" />
          ) : (
            <XCircle className="h-4 w-4 text-muted-foreground/40" />
          )}
        </span>
      </TooltipTrigger>
      <TooltipContent>
        {allowed ? "Allowed" : "Not allowed"}
      </TooltipContent>
    </Tooltip>
  )
}
