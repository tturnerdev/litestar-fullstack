import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ChevronDown, Clock, Crown, Mail, Shield, User, UserMinus, X } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"
import { InviteMemberDialog } from "@/components/teams/invite-member-dialog"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Separator } from "@/components/ui/separator"
import { useAuthStore } from "@/lib/auth"
import {
  deleteTeamInvitation,
  listTeamInvitations,
  removeMemberFromTeam,
  type Team,
  type TeamInvitation,
  type TeamMember,
  type TeamRoles,
  updateTeamMember,
} from "@/lib/generated/api"

function getMemberInitials(name: string | null | undefined, email: string): string {
  if (name) {
    return name
      .split(/\s+/)
      .map((w) => w[0])
      .join("")
      .toUpperCase()
      .slice(0, 2)
  }
  return email.slice(0, 2).toUpperCase()
}

function getMemberColor(identifier: string): string {
  const colors = [
    "bg-blue-500/15 text-blue-600 dark:text-blue-400",
    "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
    "bg-violet-500/15 text-violet-600 dark:text-violet-400",
    "bg-amber-500/15 text-amber-600 dark:text-amber-400",
    "bg-rose-500/15 text-rose-600 dark:text-rose-400",
    "bg-cyan-500/15 text-cyan-600 dark:text-cyan-400",
    "bg-fuchsia-500/15 text-fuchsia-600 dark:text-fuchsia-400",
    "bg-orange-500/15 text-orange-600 dark:text-orange-400",
  ]
  const index = identifier.split("").reduce((acc, char) => acc + char.charCodeAt(0), 0) % colors.length
  return colors[index]
}

interface TeamMembersProps {
  team: Team
  teamId: string
  canManageMembers: boolean
  isOwner: boolean
}

export function TeamMembers({ team, teamId, canManageMembers, isOwner }: TeamMembersProps) {
  const queryClient = useQueryClient()
  const { user } = useAuthStore()
  const [removeMember, setRemoveMember] = useState<TeamMember | null>(null)
  const members = team.members ?? []

  const { data: invitationsData } = useQuery({
    queryKey: ["teamInvitations", teamId],
    queryFn: async () => {
      const response = await listTeamInvitations({
        path: { team_id: teamId },
      })
      return response.data?.items ?? []
    },
    enabled: !!team,
  })

  const pendingInvitations = invitationsData?.filter((inv) => !inv.isAccepted) ?? []

  const removeMemberMutation = useMutation({
    mutationFn: async (memberEmail: string) => {
      const response = await removeMemberFromTeam({
        path: { team_id: teamId },
        body: { userName: memberEmail },
      })
      if (response.error) {
        throw new Error(response.error.detail || "Failed to remove member")
      }
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["team", teamId] })
      toast.success("Member removed", {
        description: `${removeMember?.name ?? removeMember?.email} has been removed from the team.`,
      })
      setRemoveMember(null)
    },
    onError: (error: Error) => {
      toast.error("Failed to remove member", {
        description: error.message,
      })
    },
  })

  const updateRoleMutation = useMutation({
    mutationFn: async ({ userId, role }: { userId: string; role: TeamRoles }) => {
      const response = await updateTeamMember({
        path: { team_id: teamId, user_id: userId },
        body: { role },
      })
      if (response.error) {
        throw new Error(response.error.detail || "Failed to update role")
      }
      return response.data
    },
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["team", teamId] })
      toast.success("Role updated", {
        description: `Member role changed to ${variables.role.toLowerCase()}.`,
      })
    },
    onError: (error: Error) => {
      toast.error("Failed to update role", {
        description: error.message,
      })
    },
  })

  const cancelInvitationMutation = useMutation({
    mutationFn: async (invitationId: string) => {
      const response = await deleteTeamInvitation({
        path: { team_id: teamId, invitation_id: invitationId },
      })
      if (response.error) {
        throw new Error(response.error.detail || "Failed to cancel invitation")
      }
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["teamInvitations", teamId] })
      toast.success("Invitation cancelled")
    },
    onError: (error: Error) => {
      toast.error("Failed to cancel invitation", {
        description: error.message,
      })
    },
  })

  const canRemoveMember = (member: TeamMember) => {
    if (member.isOwner) return false
    if (member.userId === user?.id && !user?.isSuperuser) return false
    return canManageMembers
  }

  const canChangeRole = (member: TeamMember) => {
    if (member.isOwner) return false
    if (member.userId === user?.id) return false
    return isOwner || user?.isSuperuser
  }

  const getRoleBadge = (member: TeamMember) => {
    if (member.isOwner) {
      return (
        <Badge className="gap-1 bg-amber-500/15 text-amber-700 hover:bg-amber-500/20 dark:text-amber-400">
          <Crown className="h-3 w-3" />
          Owner
        </Badge>
      )
    }
    if (member.role === "ADMIN") {
      return (
        <Badge variant="outline" className="gap-1 border-blue-500/30 text-blue-600 dark:text-blue-400">
          <Shield className="h-3 w-3" />
          Admin
        </Badge>
      )
    }
    return (
      <Badge variant="outline" className="gap-1">
        <User className="h-3 w-3" />
        Member
      </Badge>
    )
  }

  return (
    <div className="space-y-6">
      <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <div className="space-y-1.5">
            <CardTitle>Members</CardTitle>
            <CardDescription>
              {members.length} member{members.length !== 1 ? "s" : ""} in this team
            </CardDescription>
          </div>
          {canManageMembers && <InviteMemberDialog teamId={teamId} />}
        </CardHeader>
        <CardContent className="space-y-2">
          {members.map((member: TeamMember) => {
            const isSelf = member.userId === user?.id
            const colorClass = getMemberColor(member.email)

            return (
              <div
                key={member.id}
                className={`flex items-center justify-between rounded-xl border p-3 transition-colors ${isSelf ? "border-primary/30 bg-primary/5" : "border-border/60 bg-background/60 hover:bg-muted/30"}`}
              >
                <div className="flex items-center gap-3">
                  <Avatar className={`h-9 w-9 ${colorClass}`}>
                    <AvatarFallback className={`text-xs font-semibold ${colorClass}`}>
                      {getMemberInitials(member.name, member.email)}
                    </AvatarFallback>
                  </Avatar>
                  <div className="flex flex-col">
                    <div className="flex items-center gap-2">
                      <p className="font-medium text-sm text-foreground">{member.name ?? member.email}</p>
                      {isSelf && (
                        <Badge variant="secondary" className="text-[10px]">
                          You
                        </Badge>
                      )}
                    </div>
                    <p className="text-muted-foreground text-xs">{member.email}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {canChangeRole(member) ? (
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="sm" className="h-7 gap-1 px-2 text-xs">
                          {getRoleBadge(member)}
                          <ChevronDown className="h-3 w-3 text-muted-foreground" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="w-48">
                        <DropdownMenuLabel>Change role</DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          onClick={() => updateRoleMutation.mutate({ userId: member.userId, role: "ADMIN" })}
                          disabled={member.role === "ADMIN"}
                        >
                          <Shield className="mr-2 h-4 w-4 text-blue-500" />
                          <div>
                            <p className="font-medium">Admin</p>
                            <p className="text-xs text-muted-foreground">Can manage members and settings</p>
                          </div>
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => updateRoleMutation.mutate({ userId: member.userId, role: "MEMBER" })}
                          disabled={member.role === "MEMBER" || !member.role}
                        >
                          <User className="mr-2 h-4 w-4" />
                          <div>
                            <p className="font-medium">Member</p>
                            <p className="text-xs text-muted-foreground">Can view and collaborate</p>
                          </div>
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  ) : (
                    getRoleBadge(member)
                  )}
                  {canRemoveMember(member) && (
                    <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive" onClick={() => setRemoveMember(member)}>
                      <UserMinus className="h-4 w-4" />
                      <span className="sr-only">Remove member</span>
                    </Button>
                  )}
                </div>
              </div>
            )
          })}
          {members.length === 0 && <div className="py-8 text-center text-sm text-muted-foreground">No members yet. Invite someone to get started.</div>}
        </CardContent>
      </Card>

      {/* Pending Invitations */}
      {pendingInvitations.length > 0 && (
        <Card className="border-border/60 border-dashed bg-card/80">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Clock className="h-4 w-4 text-muted-foreground" />
              Pending invitations
            </CardTitle>
            <CardDescription>
              {pendingInvitations.length} invitation{pendingInvitations.length !== 1 ? "s" : ""} awaiting response
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {pendingInvitations.map((invitation: TeamInvitation) => (
              <div key={invitation.id} className="flex items-center justify-between rounded-lg border border-dashed border-border/60 bg-muted/30 p-3">
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-full bg-muted">
                    <Mail className="h-4 w-4 text-muted-foreground" />
                  </div>
                  <div>
                    <p className="text-sm font-medium">{invitation.email}</p>
                    <p className="text-xs text-muted-foreground">
                      Invited as {invitation.role.toLowerCase()} &middot; {new Date(invitation.createdAt).toLocaleDateString()}
                    </p>
                  </div>
                </div>
                {canManageMembers && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
                    onClick={() => cancelInvitationMutation.mutate(invitation.id)}
                    disabled={cancelInvitationMutation.isPending}
                  >
                    <X className="h-4 w-4" />
                    <span className="sr-only">Cancel invitation</span>
                  </Button>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Remove Member Confirmation Dialog */}
      <Dialog open={!!removeMember} onOpenChange={(open) => !open && setRemoveMember(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Remove member</DialogTitle>
            <DialogDescription>
              Are you sure you want to remove <strong>{removeMember?.name ?? removeMember?.email}</strong> from this team? They will lose access to all team resources.
            </DialogDescription>
          </DialogHeader>
          <Separator />
          <DialogFooter>
            <Button variant="ghost" onClick={() => setRemoveMember(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={removeMemberMutation.isPending}
              onClick={() => removeMember && removeMemberMutation.mutate(removeMember.email)}
            >
              {removeMemberMutation.isPending ? "Removing..." : "Remove member"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
