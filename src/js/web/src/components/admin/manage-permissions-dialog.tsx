import { useCallback, useEffect, useMemo, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  BarChart3,
  Cable,
  CheckCircle2,
  Clock,
  CreditCard,
  GitBranch,
  Info,
  LifeBuoy,
  Loader2,
  Lock,
  MapPin,
  Monitor,
  Phone,
  Printer,
  Save,
  ShieldAlert,
  Users,
  XCircle,
} from "lucide-react"
import type { LucideIcon } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useAdminUser } from "@/lib/api/hooks/admin"
import {
  listTeamPermissions,
  updateTeamPermissions,
  type TeamRolePermission,
  type TeamRolePermissionEntry,
  type FeatureArea,
  type TeamRoles,
} from "@/lib/generated/api"

interface ManagePermissionsDialogProps {
  userId: string
  open: boolean
  onOpenChange: (open: boolean) => void
}

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

/** Build the default permission matrix (ADMIN=full, MEMBER=view-only). */
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

/** Merge server permission rows onto the default matrix. */
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

/** Flatten the matrix back to an array of permission entries for the PUT body. */
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

export function ManagePermissionsDialog({ userId, open, onOpenChange }: ManagePermissionsDialogProps) {
  const { data: user, isLoading } = useAdminUser(userId)
  const queryClient = useQueryClient()

  const teams = user?.teams ?? []

  // Track which team is being edited (null = overview mode)
  const [editingTeamId, setEditingTeamId] = useState<string | null>(null)

  // Reset editing state when dialog closes
  useEffect(() => {
    if (!open) {
      setEditingTeamId(null)
    }
  }, [open])

  const editingTeam = useMemo(
    () => teams.find((t) => t.teamId === editingTeamId),
    [teams, editingTeamId],
  )

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Lock className="h-5 w-5 text-muted-foreground" />
            Manage Permissions
          </DialogTitle>
          <DialogDescription>
            {editingTeamId
              ? `Edit role permissions for ${editingTeam?.teamName ?? "team"}.`
              : "View and edit the effective permissions for this user based on their team roles."}
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        ) : editingTeamId ? (
          <TeamPermissionEditor
            teamId={editingTeamId}
            teamName={editingTeam?.teamName ?? "Team"}
            onBack={() => setEditingTeamId(null)}
            onSaved={() => {
              queryClient.invalidateQueries({ queryKey: ["admin", "user", userId] })
            }}
          />
        ) : teams.length === 0 ? (
          <div className="py-4 space-y-3">
            <p className="text-sm text-muted-foreground">
              This user is not a member of any teams, so no team-level permissions apply.
            </p>
            {user?.isSuperuser && (
              <div className="flex items-center gap-2 rounded-md border border-blue-200 bg-blue-50 px-3 py-2 text-sm text-blue-800 dark:border-blue-900 dark:bg-blue-950 dark:text-blue-200">
                <Lock className="h-4 w-4 shrink-0" />
                This user is a superuser and has full access to all features.
              </div>
            )}
          </div>
        ) : (
          <div className="space-y-5 max-h-[60vh] overflow-y-auto">
            {user?.isSuperuser && (
              <div className="flex items-center gap-2 rounded-md border border-blue-200 bg-blue-50 px-3 py-2 text-sm text-blue-800 dark:border-blue-900 dark:bg-blue-950 dark:text-blue-200">
                <Lock className="h-4 w-4 shrink-0" />
                This user is a superuser and has full access regardless of team permissions.
              </div>
            )}

            {teams.map((team) => (
              <TeamPermissionSummary
                key={team.teamId}
                teamId={team.teamId}
                teamName={team.teamName ?? "Unnamed team"}
                role={team.role ?? "MEMBER"}
                isOwner={team.isOwner ?? false}
                onEdit={() => setEditingTeamId(team.teamId)}
              />
            ))}
          </div>
        )}

        {!editingTeamId && (
          <DialogFooter>
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Close
            </Button>
          </DialogFooter>
        )}
      </DialogContent>
    </Dialog>
  )
}

// -- Team permission summary (read-only overview with edit button) -----------

function TeamPermissionSummary({
  teamId,
  teamName,
  role,
  isOwner,
  onEdit,
}: {
  teamId: string
  teamName: string
  role: string
  isOwner: boolean
  onEdit: () => void
}) {
  const { data: permissions, isLoading } = useQuery({
    queryKey: ["team-permissions", teamId],
    queryFn: async () => {
      const response = await listTeamPermissions({
        path: { team_id: teamId },
      })
      return response.data as TeamRolePermission[]
    },
  })

  const matrix = useMemo(() => {
    if (!permissions) return buildDefaultPermissions()
    return mergeServerPermissions(permissions)
  }, [permissions])

  const rolePerms = matrix[role] ?? matrix.MEMBER ?? {}

  const allowed = Object.values(rolePerms).reduce(
    (acc, p) => acc + (p.canView ? 1 : 0) + (p.canEdit ? 1 : 0),
    0,
  )
  const total = Object.keys(rolePerms).length * 2

  return (
    <div className="space-y-2 rounded-lg border p-4 transition-shadow hover:shadow-sm">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Users className="h-4 w-4 text-muted-foreground" />
          <h4 className="text-sm font-medium">{teamName}</h4>
          <Badge variant="outline" className="text-xs">
            {role}
          </Badge>
          {isOwner && (
            <Badge variant="secondary" className="text-xs">
              Owner
            </Badge>
          )}
        </div>
        <Button variant="outline" size="sm" onClick={onEdit}>
          Edit permissions
        </Button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-4">
          <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <>
          <div className="overflow-x-auto rounded-md border">
            <Table aria-label="Feature permissions summary">
              <TableHeader>
                <TableRow>
                  <TableHead>Feature Area</TableHead>
                  <TableHead className="w-24 text-center">View</TableHead>
                  <TableHead className="w-24 text-center">Edit</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {FEATURE_AREAS.map((area) => {
                  const perm = rolePerms[area.key] ?? { canView: false, canEdit: false }
                  return (
                    <TableRow key={area.key} className="hover:bg-muted/50">
                      <TableCell className="text-sm">
                        <div className="flex items-center gap-2">
                          <area.icon className="h-4 w-4 text-muted-foreground" />
                          {area.label}
                        </div>
                      </TableCell>
                      <TableCell className="text-center">
                        <PermissionIndicator allowed={perm.canView} />
                      </TableCell>
                      <TableCell className="text-center">
                        <PermissionIndicator allowed={perm.canEdit} />
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
          <div className="flex justify-end">
            <span className="text-xs text-muted-foreground">
              {allowed}/{total} permissions granted
            </span>
          </div>
        </>
      )}
    </div>
  )
}

// -- Team permission editor (editable grid) ---------------------------------

function TeamPermissionEditor({
  teamId,
  teamName,
  onBack,
  onSaved,
}: {
  teamId: string
  teamName: string
  onBack: () => void
  onSaved: () => void
}) {
  const queryClient = useQueryClient()

  const { data: serverPermissions, isLoading } = useQuery({
    queryKey: ["team-permissions", teamId],
    queryFn: async () => {
      const response = await listTeamPermissions({
        path: { team_id: teamId },
      })
      return response.data as TeamRolePermission[]
    },
  })

  // Local editable state
  const [matrix, setMatrix] = useState<
    Record<string, Record<string, { canView: boolean; canEdit: boolean }>>
  >(() => buildDefaultPermissions())
  const [initialized, setInitialized] = useState(false)

  // Seed local state from server data once loaded
  useEffect(() => {
    if (serverPermissions && !initialized) {
      setMatrix(mergeServerPermissions(serverPermissions))
      setInitialized(true)
    }
  }, [serverPermissions, initialized])

  // Reset initialized when teamId changes
  useEffect(() => {
    setInitialized(false)
  }, [teamId])

  const togglePermission = useCallback(
    (role: string, featureArea: string, field: "canView" | "canEdit") => {
      setMatrix((prev) => {
        const next = { ...prev }
        next[role] = { ...next[role] }
        next[role][featureArea] = { ...next[role][featureArea] }
        const current = next[role][featureArea][field]
        next[role][featureArea][field] = !current
        // If disabling view, also disable edit
        if (field === "canView" && current) {
          next[role][featureArea].canEdit = false
        }
        // If enabling edit, also enable view
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
      const entries = matrixToEntries(matrix)
      const response = await updateTeamPermissions({
        path: { team_id: teamId },
        body: { permissions: entries },
      })
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["team-permissions", teamId] })
      onSaved()
      toast.success("Permissions updated")
      onBack()
    },
    onError: (error) => {
      toast.error("Failed to update permissions", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-8">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-4 max-h-[60vh] overflow-y-auto">
      <div className="flex items-center gap-2 rounded-md border border-blue-200 bg-blue-50 px-3 py-2 text-sm text-blue-800 dark:border-blue-900 dark:bg-blue-950 dark:text-blue-200">
        <Info className="h-4 w-4 shrink-0" />
        <span>
          Editing permissions for <strong>{teamName}</strong>. Changes affect all users with the
          corresponding role in this team.
        </span>
      </div>

      <div className="overflow-x-auto rounded-md border">
        <Table aria-label="Edit role permissions">
          <TableHeader>
            <TableRow>
              <TableHead>Feature Area</TableHead>
              {ROLES.map((role) => (
                <TableHead key={`${role}-view`} className="w-24 text-center">
                  <div className="text-xs leading-tight">
                    <div>{role}</div>
                    <div className="text-muted-foreground">View</div>
                  </div>
                </TableHead>
              ))}
              {ROLES.map((role) => (
                <TableHead key={`${role}-edit`} className="w-24 text-center">
                  <div className="text-xs leading-tight">
                    <div>{role}</div>
                    <div className="text-muted-foreground">Edit</div>
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
                  const perm = matrix[role]?.[area.key] ?? { canView: false, canEdit: false }
                  return (
                    <TableCell key={`${role}-view`} className="text-center">
                      <div className="flex justify-center">
                        <Checkbox
                          checked={perm.canView}
                          onChange={() => togglePermission(role, area.key, "canView")}
                          disabled={saveMutation.isPending}
                          aria-label={`${role} can view ${area.label}`}
                        />
                      </div>
                    </TableCell>
                  )
                })}
                {ROLES.map((role) => {
                  const perm = matrix[role]?.[area.key] ?? { canView: false, canEdit: false }
                  return (
                    <TableCell key={`${role}-edit`} className="text-center">
                      <div className="flex justify-center">
                        <Checkbox
                          checked={perm.canEdit}
                          onChange={() => togglePermission(role, area.key, "canEdit")}
                          disabled={saveMutation.isPending}
                          aria-label={`${role} can edit ${area.label}`}
                        />
                      </div>
                    </TableCell>
                  )
                })}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <DialogFooter className="gap-2 sm:gap-0">
        <Button variant="outline" onClick={onBack} disabled={saveMutation.isPending}>
          Back
        </Button>
        <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>
          {saveMutation.isPending ? (
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          ) : (
            <Save className="mr-2 h-4 w-4" />
          )}
          Save permissions
        </Button>
      </DialogFooter>
    </div>
  )
}

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
