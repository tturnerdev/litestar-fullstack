import { Info, Loader2, Lock, Users } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Separator } from "@/components/ui/separator"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useAdminUser } from "@/lib/api/hooks/admin"

interface ManagePermissionsDialogProps {
  userId: string
  open: boolean
  onOpenChange: (open: boolean) => void
}

const FEATURE_AREAS = [
  { key: "voice", label: "Voice" },
  { key: "fax", label: "Fax" },
  { key: "devices", label: "Devices" },
  { key: "support", label: "Support" },
  { key: "billing", label: "Billing" },
  { key: "reporting", label: "Reporting" },
] as const

function getRolePermissions(role: string | null | undefined): Record<string, { canView: boolean; canEdit: boolean }> {
  const permissions: Record<string, { canView: boolean; canEdit: boolean }> = {}
  for (const area of FEATURE_AREAS) {
    if (role === "ADMIN") {
      permissions[area.key] = { canView: true, canEdit: true }
    } else {
      permissions[area.key] = { canView: true, canEdit: false }
    }
  }
  return permissions
}

export function ManagePermissionsDialog({ userId, open, onOpenChange }: ManagePermissionsDialogProps) {
  const { data: user, isLoading } = useAdminUser(userId)

  const teams = user?.teams ?? []

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Manage Permissions</DialogTitle>
          <DialogDescription>
            View the effective permissions for this user based on their team roles.
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
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

            {teams.map((team) => {
              const permissions = getRolePermissions(team.role)
              return (
                <div key={team.teamId} className="space-y-2">
                  <div className="flex items-center gap-2">
                    <Users className="h-4 w-4 text-muted-foreground" />
                    <h4 className="text-sm font-medium">{team.teamName}</h4>
                    <Badge variant="outline" className="text-xs">
                      {team.role ?? "MEMBER"}
                    </Badge>
                    {team.isOwner && (
                      <Badge variant="secondary" className="text-xs">
                        Owner
                      </Badge>
                    )}
                  </div>
                  <div className="rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Feature Area</TableHead>
                          <TableHead className="w-24 text-center">View</TableHead>
                          <TableHead className="w-24 text-center">Edit</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {FEATURE_AREAS.map((area) => {
                          const perm = permissions[area.key]
                          return (
                            <TableRow key={area.key}>
                              <TableCell className="text-sm">{area.label}</TableCell>
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
                </div>
              )
            })}

            <Separator />

            <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200">
              <Info className="mt-0.5 h-4 w-4 shrink-0" />
              <div>
                <p className="font-medium">Per-user permission overrides coming soon</p>
                <p className="mt-1 text-xs">
                  The permissions shown above are derived from the user's team role. Per-user
                  overrides that supersede team role permissions will be available in a future update.
                </p>
              </div>
            </div>
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function PermissionIndicator({ allowed }: { allowed: boolean }) {
  return (
    <span
      className={`inline-block h-2.5 w-2.5 rounded-full ${
        allowed ? "bg-green-500" : "bg-muted-foreground/30"
      }`}
      title={allowed ? "Allowed" : "Not allowed"}
    />
  )
}
