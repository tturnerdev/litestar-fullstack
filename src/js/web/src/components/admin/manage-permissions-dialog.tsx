import { BarChart3, CheckCircle2, CreditCard, Info, LifeBuoy, Loader2, Lock, Monitor, Phone, Printer, Users, XCircle } from "lucide-react"
import type { LucideIcon } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Separator } from "@/components/ui/separator"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useAdminUser } from "@/lib/api/hooks/admin"

interface ManagePermissionsDialogProps {
  userId: string
  open: boolean
  onOpenChange: (open: boolean) => void
}

const FEATURE_AREAS: readonly { key: string; label: string; icon: LucideIcon }[] = [
  { key: "voice", label: "Voice", icon: Phone },
  { key: "fax", label: "Fax", icon: Printer },
  { key: "devices", label: "Devices", icon: Monitor },
  { key: "support", label: "Support", icon: LifeBuoy },
  { key: "billing", label: "Billing", icon: CreditCard },
  { key: "reporting", label: "Reporting", icon: BarChart3 },
]

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

function countAllowed(permissions: Record<string, { canView: boolean; canEdit: boolean }>): { allowed: number; total: number } {
  let allowed = 0
  let total = 0
  for (const key of Object.keys(permissions)) {
    if (permissions[key].canView) allowed++
    if (permissions[key].canEdit) allowed++
    total += 2
  }
  return { allowed, total }
}

export function ManagePermissionsDialog({ userId, open, onOpenChange }: ManagePermissionsDialogProps) {
  const { data: user, isLoading } = useAdminUser(userId)

  const teams = user?.teams ?? []

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Lock className="h-5 w-5 text-muted-foreground" />
            Manage Permissions
          </DialogTitle>
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
              const { allowed, total } = countAllowed(permissions)
              return (
                <div key={team.teamId} className="space-y-2 rounded-lg border p-4 transition-shadow hover:shadow-sm">
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
