import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Check, Loader2, Save, Shield } from "lucide-react"
import { useCallback, useEffect, useState } from "react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  type FeatureArea,
  listTeamPermissions,
  type TeamRolePermission,
  type TeamRolePermissionEntry,
  updateTeamPermissions,
} from "@/lib/generated/api"

const FEATURE_AREAS: { value: FeatureArea; label: string }[] = [
  { value: "DEVICES", label: "Devices" },
  { value: "VOICE", label: "Voice" },
  { value: "FAX", label: "Fax" },
  { value: "SUPPORT", label: "Support" },
  { value: "ORGANIZATION", label: "Organization" },
  { value: "TEAMS", label: "Teams" },
]

const ROLES = ["ADMIN", "MEMBER"] as const
type Role = (typeof ROLES)[number]

type PermMatrix = Record<Role, Record<FeatureArea, { view: boolean; edit: boolean }>>

function buildMatrix(permissions: TeamRolePermission[]): PermMatrix {
  const matrix: PermMatrix = {} as PermMatrix
  for (const role of ROLES) {
    matrix[role] = {} as Record<FeatureArea, { view: boolean; edit: boolean }>
    for (const area of FEATURE_AREAS) {
      matrix[role][area.value] = { view: false, edit: false }
    }
  }
  for (const p of permissions) {
    const role = p.role as Role
    if (matrix[role]?.[p.featureArea]) {
      matrix[role][p.featureArea] = { view: p.canView, edit: p.canEdit }
    }
  }
  return matrix
}

function matrixToEntries(matrix: PermMatrix): TeamRolePermissionEntry[] {
  const entries: TeamRolePermissionEntry[] = []
  for (const role of ROLES) {
    for (const area of FEATURE_AREAS) {
      const cell = matrix[role][area.value]
      if (cell.view || cell.edit) {
        entries.push({
          role,
          featureArea: area.value,
          canView: cell.view,
          canEdit: cell.edit,
        })
      }
    }
  }
  return entries
}

interface TeamPermissionsProps {
  teamId: string
  canEdit: boolean
}

export function TeamPermissions({ teamId, canEdit }: TeamPermissionsProps) {
  const queryClient = useQueryClient()
  const [matrix, setMatrix] = useState<PermMatrix | null>(null)
  const [dirty, setDirty] = useState(false)

  const { data: permissions, isLoading } = useQuery({
    queryKey: ["teamPermissions", teamId],
    queryFn: async () => {
      const res = await listTeamPermissions({ path: { team_id: teamId } })
      return res.data ?? []
    },
  })

  useEffect(() => {
    if (permissions) {
      setMatrix(buildMatrix(permissions))
      setDirty(false)
    }
  }, [permissions])

  const saveMutation = useMutation({
    mutationFn: async (entries: TeamRolePermissionEntry[]) => {
      const res = await updateTeamPermissions({
        path: { team_id: teamId },
        body: { permissions: entries },
      })
      return res.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["teamPermissions", teamId] })
      setDirty(false)
      toast.success("Permissions saved")
    },
    onError: () => {
      toast.error("Failed to save permissions")
    },
  })

  const toggle = useCallback(
    (role: Role, area: FeatureArea, field: "view" | "edit") => {
      if (!canEdit || !matrix) return
      setMatrix((prev) => {
        if (!prev) return prev
        const next = structuredClone(prev)
        const cell = next[role][area]
        if (field === "edit") {
          cell.edit = !cell.edit
          if (cell.edit) cell.view = true
        } else {
          cell.view = !cell.view
          if (!cell.view) cell.edit = false
        }
        return next
      })
      setDirty(true)
    },
    [canEdit, matrix],
  )

  const handleSave = () => {
    if (!matrix) return
    saveMutation.mutate(matrixToEntries(matrix))
  }

  if (isLoading || !matrix) {
    return (
      <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
        <CardContent className="flex items-center justify-center py-8">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
      <CardHeader className="flex flex-row items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-muted-foreground" />
          <CardTitle>Role Permissions</CardTitle>
        </div>
        {canEdit && dirty && (
          <Button size="sm" onClick={handleSave} disabled={saveMutation.isPending}>
            {saveMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
            Save
          </Button>
        )}
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/60">
                <th className="py-2 pr-4 text-left font-medium text-muted-foreground">Feature Area</th>
                {ROLES.map((role) => (
                  <th key={role} colSpan={2} className="px-2 py-2 text-center font-medium">
                    <Badge variant="outline" className="uppercase">
                      {role}
                    </Badge>
                  </th>
                ))}
              </tr>
              <tr className="border-b border-border/40">
                <th />
                {ROLES.map((role) => (
                  <PermColumnHeaders key={role} />
                ))}
              </tr>
            </thead>
            <tbody>
              {FEATURE_AREAS.map((area) => (
                <tr key={area.value} className="border-b border-border/30 transition-colors hover:bg-muted/30">
                  <td className="py-2.5 pr-4 font-medium text-foreground">{area.label}</td>
                  {ROLES.map((role) => {
                    const cell = matrix[role][area.value]
                    return (
                      <PermCells
                        key={role}
                        view={cell.view}
                        edit={cell.edit}
                        disabled={!canEdit}
                        onToggleView={() => toggle(role, area.value, "view")}
                        onToggleEdit={() => toggle(role, area.value, "edit")}
                      />
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!canEdit && (
          <p className="mt-3 text-xs text-muted-foreground">Only team admins can modify permissions.</p>
        )}
      </CardContent>
    </Card>
  )
}

function PermColumnHeaders() {
  return (
    <>
      <th className="px-2 py-1 text-center text-xs font-normal text-muted-foreground">View</th>
      <th className="px-2 py-1 text-center text-xs font-normal text-muted-foreground">Edit</th>
    </>
  )
}

function PermCells({
  view,
  edit,
  disabled,
  onToggleView,
  onToggleEdit,
}: {
  view: boolean
  edit: boolean
  disabled: boolean
  onToggleView: () => void
  onToggleEdit: () => void
}) {
  return (
    <>
      <td className="px-2 py-2.5 text-center">
        <PermCheckbox checked={view} disabled={disabled} onChange={onToggleView} />
      </td>
      <td className="px-2 py-2.5 text-center">
        <PermCheckbox checked={edit} disabled={disabled} onChange={onToggleEdit} />
      </td>
    </>
  )
}

function PermCheckbox({
  checked,
  disabled,
  onChange,
}: {
  checked: boolean
  disabled: boolean
  onChange: () => void
}) {
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={checked}
      disabled={disabled}
      onClick={onChange}
      className={`inline-flex h-5 w-5 items-center justify-center rounded-md border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50 ${
        checked
          ? "border-primary bg-primary text-primary-foreground"
          : "border-border bg-background text-transparent hover:border-primary/50"
      } ${disabled ? "cursor-not-allowed opacity-50" : "cursor-pointer"}`}
    >
      <Check className="h-3.5 w-3.5" strokeWidth={3} />
    </button>
  )
}
