import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  CheckCircle2,
  Info,
  Loader2,
  Lock,
  Save,
  Users,
  XCircle,
} from "lucide-react"
import { Fragment, useCallback, useEffect, useMemo, useState } from "react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useAdminUser } from "@/lib/api/hooks/admin"
import { type FeatureArea, listTeamPermissions, type TeamRolePermission, updateTeamPermissions } from "@/lib/generated/api"
import { buildDefaultPermissions, FEATURE_AREAS, type FeatureAreaNode, matrixToEntries, mergeServerPermissions, type PermissionMatrix, ROLES } from "@/lib/permissions"

interface ManagePermissionsDialogProps {
  userId: string
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function ManagePermissionsDialog({ userId, open, onOpenChange }: ManagePermissionsDialogProps) {
  const { data: user, isLoading } = useAdminUser(userId)
  const queryClient = useQueryClient()

  const teams = user?.teams ?? []

  const [editingTeamId, setEditingTeamId] = useState<string | null>(null)

  useEffect(() => {
    if (!open) {
      setEditingTeamId(null)
    }
  }, [open])

  const editingTeam = useMemo(() => teams.find((t) => t.teamId === editingTeamId), [teams, editingTeamId])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Lock className="h-5 w-5 text-muted-foreground" />
            Manage Permissions
          </DialogTitle>
          <DialogDescription>
            {editingTeamId ? `Edit role permissions for ${editingTeam?.teamName ?? "team"}.` : "View and edit the effective permissions for this user based on their team roles."}
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
            <p className="text-sm text-muted-foreground">This user is not a member of any teams, so no team-level permissions apply.</p>
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

// -- Permission rows helper ---------------------------------------------------

function renderPermissionRows(areas: readonly FeatureAreaNode[], rolePerms: Record<string, { canView: boolean; canEdit: boolean }>, mode: "view"): React.ReactNode
function renderPermissionRows(
  areas: readonly FeatureAreaNode[],
  matrix: PermissionMatrix,
  mode: "edit",
  opts: {
    togglePermission: (role: string, featureArea: string, field: "canView" | "canEdit") => void
    toggleParent: (role: string, parentKey: string, children: { key: FeatureArea }[], field: "canView" | "canEdit") => void
    isPending: boolean
  },
): React.ReactNode
function renderPermissionRows(
  areas: readonly FeatureAreaNode[],
  matrixOrPerms: PermissionMatrix | Record<string, { canView: boolean; canEdit: boolean }>,
  mode: "view" | "edit",
  opts?: {
    togglePermission: (role: string, featureArea: string, field: "canView" | "canEdit") => void
    toggleParent: (role: string, parentKey: string, children: { key: FeatureArea }[], field: "canView" | "canEdit") => void
    isPending: boolean
  },
): React.ReactNode {
  const rows: React.ReactNode[] = []

  for (const area of areas) {
    if (mode === "view") {
      const perms = matrixOrPerms as Record<string, { canView: boolean; canEdit: boolean }>
      const perm = perms[area.key] ?? { canView: false, canEdit: false }
      rows.push(
        <TableRow key={area.key} className="hover:bg-muted/50">
          <TableCell className="text-sm font-medium">
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
        </TableRow>,
      )
      if (area.children) {
        for (const child of area.children) {
          const childPerm = perms[child.key] ?? { canView: false, canEdit: false }
          rows.push(
            <TableRow key={child.key} className="hover:bg-muted/50">
              <TableCell className="text-sm text-muted-foreground">
                <div className="flex items-center gap-2 pl-6">
                  <child.icon className="h-3.5 w-3.5" />
                  {child.label}
                </div>
              </TableCell>
              <TableCell className="text-center">
                <PermissionIndicator allowed={childPerm.canView} />
              </TableCell>
              <TableCell className="text-center">
                <PermissionIndicator allowed={childPerm.canEdit} />
              </TableCell>
            </TableRow>,
          )
        }
      }
    } else {
      const matrix = matrixOrPerms as PermissionMatrix
      rows.push(
        <TableRow key={area.key} className="hover:bg-muted/50 bg-muted/20">
          <TableCell className="text-sm font-medium">
            <div className="flex items-center gap-2">
              <area.icon className="h-4 w-4 text-muted-foreground" />
              {area.label}
            </div>
          </TableCell>
          {ROLES.map((role) => {
            if (area.children) {
              const allView = area.children.every((c) => matrix[role]?.[c.key]?.canView)
              const noneView = area.children.every((c) => !matrix[role]?.[c.key]?.canView)
              const allEdit = area.children.every((c) => matrix[role]?.[c.key]?.canEdit)
              const noneEdit = area.children.every((c) => !matrix[role]?.[c.key]?.canEdit)
              return (
                <Fragment key={role}>
                  <TableCell className="text-center">
                    <div className="flex justify-center">
                      <Checkbox
                        checked={allView}
                        indeterminate={!allView && !noneView}
                        onChange={() => opts!.toggleParent(role, area.key, area.children!, "canView")}
                        disabled={opts!.isPending}
                        aria-label={`${role} can view all ${area.label}`}
                      />
                    </div>
                  </TableCell>
                  <TableCell className="text-center">
                    <div className="flex justify-center">
                      <Checkbox
                        checked={allEdit}
                        indeterminate={!allEdit && !noneEdit}
                        onChange={() => opts!.toggleParent(role, area.key, area.children!, "canEdit")}
                        disabled={opts!.isPending}
                        aria-label={`${role} can edit all ${area.label}`}
                      />
                    </div>
                  </TableCell>
                </Fragment>
              )
            }
            const perm = matrix[role]?.[area.key] ?? { canView: false, canEdit: false }
            return (
              <Fragment key={role}>
                <TableCell className="text-center">
                  <div className="flex justify-center">
                    <Checkbox
                      checked={perm.canView}
                      onChange={() => opts!.togglePermission(role, area.key, "canView")}
                      disabled={opts!.isPending}
                      aria-label={`${role} can view ${area.label}`}
                    />
                  </div>
                </TableCell>
                <TableCell className="text-center">
                  <div className="flex justify-center">
                    <Checkbox
                      checked={perm.canEdit}
                      onChange={() => opts!.togglePermission(role, area.key, "canEdit")}
                      disabled={opts!.isPending}
                      aria-label={`${role} can edit ${area.label}`}
                    />
                  </div>
                </TableCell>
              </Fragment>
            )
          })}
        </TableRow>,
      )
      if (area.children) {
        for (const child of area.children) {
          rows.push(
            <TableRow key={child.key} className="hover:bg-muted/50">
              <TableCell className="text-sm text-muted-foreground">
                <div className="flex items-center gap-2 pl-6">
                  <child.icon className="h-3.5 w-3.5" />
                  {child.label}
                </div>
              </TableCell>
              {ROLES.map((role) => {
                const perm = matrix[role]?.[child.key] ?? { canView: false, canEdit: false }
                return (
                  <Fragment key={role}>
                    <TableCell className="text-center">
                      <div className="flex justify-center">
                        <Checkbox
                          checked={perm.canView}
                          onChange={() => opts!.togglePermission(role, child.key, "canView")}
                          disabled={opts!.isPending}
                          aria-label={`${role} can view ${child.label}`}
                        />
                      </div>
                    </TableCell>
                    <TableCell className="text-center">
                      <div className="flex justify-center">
                        <Checkbox
                          checked={perm.canEdit}
                          onChange={() => opts!.togglePermission(role, child.key, "canEdit")}
                          disabled={opts!.isPending}
                          aria-label={`${role} can edit ${child.label}`}
                        />
                      </div>
                    </TableCell>
                  </Fragment>
                )
              })}
            </TableRow>,
          )
        }
      }
    }
  }
  return rows
}

// -- Team permission summary (read-only overview with edit button) -----------

function TeamPermissionSummary({ teamId, teamName, role, isOwner, onEdit }: { teamId: string; teamName: string; role: string; isOwner: boolean; onEdit: () => void }) {
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

  const allowed = Object.values(rolePerms).reduce((acc, p) => acc + (p.canView ? 1 : 0) + (p.canEdit ? 1 : 0), 0)
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
              <TableBody>{renderPermissionRows(FEATURE_AREAS, rolePerms, "view")}</TableBody>
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

function TeamPermissionEditor({ teamId, teamName, onBack, onSaved }: { teamId: string; teamName: string; onBack: () => void; onSaved: () => void }) {
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

  const [matrix, setMatrix] = useState<PermissionMatrix>(() => buildDefaultPermissions())
  const [initialized, setInitialized] = useState(false)

  useEffect(() => {
    if (serverPermissions && !initialized) {
      setMatrix(mergeServerPermissions(serverPermissions))
      setInitialized(true)
    }
  }, [serverPermissions, initialized])

  // biome-ignore lint/correctness/useExhaustiveDependencies: teamId is a prop we must react to
  useEffect(() => {
    setInitialized(false)
  }, [teamId])

  const togglePermission = useCallback((role: string, featureArea: string, field: "canView" | "canEdit") => {
    setMatrix((prev) => {
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

  const toggleParent = useCallback((role: string, _parentKey: string, children: { key: FeatureArea }[], field: "canView" | "canEdit") => {
    setMatrix((prev) => {
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
          Editing permissions for <strong>{teamName}</strong>. Changes affect all users with the corresponding role in this team.
        </span>
      </div>

      <div className="overflow-x-auto rounded-md border">
        <Table aria-label="Edit role permissions">
          <TableHeader>
            <TableRow>
              <TableHead>Feature Area</TableHead>
              {ROLES.map((role) => (
                <Fragment key={role}>
                  <TableHead className="w-24 text-center">
                    <div className="text-xs leading-tight">
                      <div>{role}</div>
                      <div className="text-muted-foreground">View</div>
                    </div>
                  </TableHead>
                  <TableHead className="w-24 text-center">
                    <div className="text-xs leading-tight">
                      <div>{role}</div>
                      <div className="text-muted-foreground">Edit</div>
                    </div>
                  </TableHead>
                </Fragment>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {renderPermissionRows(FEATURE_AREAS, matrix, "edit", {
              togglePermission,
              toggleParent,
              isPending: saveMutation.isPending,
            })}
          </TableBody>
        </Table>
      </div>

      <DialogFooter className="gap-2 sm:gap-0">
        <Button variant="outline" onClick={onBack} disabled={saveMutation.isPending}>
          Back
        </Button>
        <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>
          {saveMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
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
          {allowed ? <CheckCircle2 className="h-4 w-4 text-green-500" /> : <XCircle className="h-4 w-4 text-muted-foreground/40" />}
        </span>
      </TooltipTrigger>
      <TooltipContent>{allowed ? "Allowed" : "Not allowed"}</TooltipContent>
    </Tooltip>
  )
}
