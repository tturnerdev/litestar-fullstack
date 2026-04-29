import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonCard } from "@/components/ui/skeleton"
import { X } from "lucide-react"
import { useState } from "react"
import { useAdminUser, useAssignRole, useRevokeRole, useRoles } from "@/lib/api/hooks/admin"

interface ManageRolesDialogProps {
  userId: string
  userEmail: string
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function ManageRolesDialog({ userId, userEmail, open, onOpenChange }: ManageRolesDialogProps) {
  const { data: user, isLoading: userLoading } = useAdminUser(userId)
  const { data: rolesData, isLoading: rolesLoading } = useRoles()
  const assignRole = useAssignRole()
  const revokeRoleMutation = useRevokeRole()
  const [selectedRole, setSelectedRole] = useState("")

  const userRoles = user?.roles ?? []
  const allRoles = rolesData?.items ?? []
  const assignedSlugs = new Set(userRoles.map((r) => r.roleSlug))
  const availableRoles = allRoles.filter((r) => !assignedSlugs.has(r.slug))

  function handleAssign() {
    if (!selectedRole) return
    assignRole.mutate(
      { roleSlug: selectedRole, userEmail },
      {
        onSuccess: () => {
          setSelectedRole("")
        },
      },
    )
  }

  function handleRevoke(roleSlug: string) {
    revokeRoleMutation.mutate({ roleSlug, userEmail })
  }

  const isLoading = userLoading || rolesLoading

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Manage Roles</DialogTitle>
          <DialogDescription>Add or remove roles for {userEmail}.</DialogDescription>
        </DialogHeader>
        {isLoading ? (
          <SkeletonCard />
        ) : (
          <div className="space-y-4">
            <div>
              <p className="mb-2 text-sm font-medium">Current roles</p>
              {userRoles.length === 0 ? (
                <p className="text-sm text-muted-foreground">No roles assigned.</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {userRoles.map((role) => (
                    <Badge key={role.roleId} variant="secondary" className="gap-1">
                      {role.roleName}
                      <button
                        type="button"
                        onClick={() => handleRevoke(role.roleSlug)}
                        disabled={revokeRoleMutation.isPending}
                        className="ml-1 rounded-full p-0.5 hover:bg-muted"
                        aria-label={`Remove ${role.roleName} role`}
                      >
                        <X className="h-3 w-3" />
                      </button>
                    </Badge>
                  ))}
                </div>
              )}
            </div>
            {availableRoles.length > 0 && (
              <div className="space-y-2">
                <p className="text-sm font-medium">Add a role</p>
                <div className="flex gap-2">
                  <Select value={selectedRole} onValueChange={setSelectedRole}>
                    <SelectTrigger className="flex-1">
                      <SelectValue placeholder="Select a role" />
                    </SelectTrigger>
                    <SelectContent>
                      {availableRoles.map((role) => (
                        <SelectItem key={role.id} value={role.slug}>
                          {role.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Button onClick={handleAssign} disabled={!selectedRole || assignRole.isPending} size="sm">
                    {assignRole.isPending ? "Assigning..." : "Add"}
                  </Button>
                </div>
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
