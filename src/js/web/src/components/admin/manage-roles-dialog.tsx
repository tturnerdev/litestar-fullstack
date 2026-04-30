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
import { CheckCircle2, Loader2, Shield, ShieldOff, Trash2, Users, UsersRound } from "lucide-react"
import { useCallback, useEffect, useRef, useState } from "react"
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
  const [confirmingRevoke, setConfirmingRevoke] = useState<string | null>(null)
  const [changedTeamId, setChangedTeamId] = useState<string | null>(null)
  const revokeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const changeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const userRoles = user?.roles ?? []
  const allRoles = rolesData?.items ?? []
  const assignedSlugs = new Set(userRoles.map((r) => r.roleSlug))
  const availableRoles = allRoles.filter((r) => !assignedSlugs.has(r.slug))
  const teams = user?.teams ?? []

  // Clean up timers on unmount
  useEffect(() => {
    return () => {
      if (revokeTimerRef.current) clearTimeout(revokeTimerRef.current)
      if (changeTimerRef.current) clearTimeout(changeTimerRef.current)
    }
  }, [])

  const handleRevokeClick = useCallback(
    (roleSlug: string) => {
      if (confirmingRevoke === roleSlug) {
        // Confirmed -- actually revoke
        if (revokeTimerRef.current) clearTimeout(revokeTimerRef.current)
        setConfirmingRevoke(null)
        revokeRoleMutation.mutate({ roleSlug, userEmail })
      } else {
        // First click -- show confirmation
        setConfirmingRevoke(roleSlug)
        if (revokeTimerRef.current) clearTimeout(revokeTimerRef.current)
        revokeTimerRef.current = setTimeout(() => {
          setConfirmingRevoke(null)
        }, 2000)
      }
    },
    [confirmingRevoke, revokeRoleMutation, userEmail],
  )

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

  function handleTeamRoleChange(teamId: string, value: string) {
    updateTeamMember.mutate(
      { teamId, role: value as TeamRoles },
      {
        onSuccess: () => {
          setChangedTeamId(teamId)
          if (changeTimerRef.current) clearTimeout(changeTimerRef.current)
          changeTimerRef.current = setTimeout(() => {
            setChangedTeamId(null)
          }, 1500)
        },
      },
    )
  }

  const isLoading = userLoading || rolesLoading

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-muted-foreground" />
            Manage Roles
          </DialogTitle>
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
                <span className="text-xs text-muted-foreground">
                  {userRoles.length} {userRoles.length === 1 ? "role" : "roles"}
                </span>
              </div>
              {userRoles.length === 0 ? (
                <div className="flex flex-col items-center gap-2 py-4 text-center">
                  <ShieldOff className="h-8 w-8 text-muted-foreground/40" />
                  <p className="text-sm text-muted-foreground">No system roles assigned.</p>
                </div>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {userRoles.map((role) => {
                    const isConfirming = confirmingRevoke === role.roleSlug
                    return (
                      <Badge
                        key={role.roleId}
                        variant="secondary"
                        className="gap-1 bg-violet-100 text-violet-700 hover:bg-violet-100 dark:bg-violet-900/30 dark:text-violet-400 dark:hover:bg-violet-900/30"
                      >
                        {role.roleName}
                        <button
                          type="button"
                          onClick={() => handleRevokeClick(role.roleSlug)}
                          disabled={revokeRoleMutation.isPending}
                          className={`ml-1 rounded-full p-0.5 transition-colors ${
                            isConfirming
                              ? "bg-destructive/15 text-destructive hover:bg-destructive/25"
                              : "hover:bg-violet-200 dark:hover:bg-violet-800/50"
                          }`}
                          aria-label={isConfirming ? `Confirm remove ${role.roleName}` : `Remove ${role.roleName} role`}
                          title={isConfirming ? "Click again to confirm" : `Remove ${role.roleName}`}
                        >
                          <Trash2 className="h-3 w-3" />
                        </button>
                        {isConfirming && (
                          <span className="ml-0.5 text-xs text-destructive">Remove?</span>
                        )}
                      </Badge>
                    )
                  })}
                </div>
              )}
              {availableRoles.length > 0 && (
                <div className="flex gap-2">
                  <Select value={selectedRole} onValueChange={setSelectedRole} disabled={assignRole.isPending}>
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
                    {assignRole.isPending ? (
                      <>
                        <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                        Adding...
                      </>
                    ) : (
                      "Add"
                    )}
                  </Button>
                </div>
              )}
            </div>

            <Separator />

            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Users className="h-4 w-4 text-muted-foreground" />
                <h4 className="text-sm font-medium">Team Roles</h4>
                <span className="text-xs text-muted-foreground">
                  {teams.length} {teams.length === 1 ? "team" : "teams"}
                </span>
              </div>
              {teams.length === 0 ? (
                <div className="flex flex-col items-center gap-2 py-4 text-center">
                  <UsersRound className="h-8 w-8 text-muted-foreground/40" />
                  <p className="text-sm text-muted-foreground">This user is not a member of any teams.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {teams.map((team) => (
                    <div
                      key={team.teamId}
                      className="flex items-center justify-between rounded-md border px-3 py-2 transition-colors hover:bg-muted/30"
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium">{team.teamName}</span>
                        {team.isOwner && (
                          <Badge variant="outline" className="text-xs">
                            Owner
                          </Badge>
                        )}
                        {changedTeamId === team.teamId && (
                          <CheckCircle2 className="h-4 w-4 text-green-500 animate-in fade-in zoom-in duration-200" />
                        )}
                      </div>
                      <Select
                        value={team.role ?? "MEMBER"}
                        onValueChange={(value) => handleTeamRoleChange(team.teamId, value)}
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
