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
import { Separator } from "@/components/ui/separator"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Shield, Users, X } from "lucide-react"
import { useState } from "react"
import { useAdminUser, useAssignRole, useRevokeRole, useRoles, useUpdateTeamMember } from "@/lib/api/hooks/admin"
import type { TeamRoles } from "@/lib/generated/api"

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
  const updateTeamMember = useUpdateTeamMember(userId)
  const [selectedRole, setSelectedRole] = useState("")

  const userRoles = user?.roles ?? []
  const allRoles = rolesData?.items ?? []
  const assignedSlugs = new Set(userRoles.map((r) => r.roleSlug))
  const availableRoles = allRoles.filter((r) => !assignedSlugs.has(r.slug))
  const teams = user?.teams ?? []

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
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Manage Roles</DialogTitle>
          <DialogDescription>Manage system and team roles for {userEmail}.</DialogDescription>
        </DialogHeader>
        {isLoading ? (
          <SkeletonCard />
        ) : (
          <div className="space-y-5">
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-muted-foreground" />
                <h4 className="text-sm font-medium">System Roles</h4>
              </div>
              {userRoles.length === 0 ? (
                <p className="text-sm text-muted-foreground">No system roles assigned.</p>
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
              {availableRoles.length > 0 && (
                <div className="flex gap-2">
                  <Select value={selectedRole} onValueChange={setSelectedRole}>
                    <SelectTrigger className="flex-1">
                      <SelectValue placeholder="Add role..." />
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
              )}
            </div>

            <Separator />

            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Users className="h-4 w-4 text-muted-foreground" />
                <h4 className="text-sm font-medium">Team Roles</h4>
              </div>
              {teams.length === 0 ? (
                <p className="text-sm text-muted-foreground">This user is not a member of any teams.</p>
              ) : (
                <div className="space-y-2">
                  {teams.map((team) => (
                    <div key={team.teamId} className="flex items-center justify-between rounded-md border px-3 py-2">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium">{team.teamName}</span>
                        {team.isOwner && (
                          <Badge variant="outline" className="text-xs">
                            Owner
                          </Badge>
                        )}
                      </div>
                      <Select
                        value={team.role ?? "MEMBER"}
                        onValueChange={(value) => updateTeamMember.mutate({ teamId: team.teamId, role: value as TeamRoles })}
                        disabled={updateTeamMember.isPending || team.isOwner}
                      >
                        <SelectTrigger className="w-28">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="MEMBER">Member</SelectItem>
                          <SelectItem value="ADMIN">Admin</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
