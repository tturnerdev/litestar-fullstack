import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { AlertTriangle, ChevronDown, Clock, Crown, Loader2, Mail, RotateCw, Search, Shield, User, UserMinus, X } from "lucide-react"
import { useMemo, useState } from "react"
import { toast } from "sonner"
import { InviteMemberDialog } from "@/components/teams/invite-member-dialog"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { BulkActionBar, type BulkAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"
import { formatRelativeTimeShort } from "@/lib/date-utils"
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

type RoleFilter = "ALL" | "OWNER" | "ADMIN" | "MEMBER"

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
  const [searchQuery, setSearchQuery] = useState("")
  const [roleFilter, setRoleFilter] = useState<RoleFilter>("ALL")
  const [selected, setSelected] = useState<Set<string>>(new Set())
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

  const roleCounts = useMemo(() => {
    let owners = 0
    let admins = 0
    let memberCount = 0
    for (const m of members) {
      if (m.isOwner) owners++
      else if (m.role === "ADMIN") admins++
      else memberCount++
    }
    return { owners, admins, members: memberCount }
  }, [members])

  const roleCountDescription = useMemo(() => {
    const parts: string[] = []
    if (roleCounts.owners > 0) parts.push(`${roleCounts.owners} owner${roleCounts.owners !== 1 ? "s" : ""}`)
    if (roleCounts.admins > 0) parts.push(`${roleCounts.admins} admin${roleCounts.admins !== 1 ? "s" : ""}`)
    if (roleCounts.members > 0) parts.push(`${roleCounts.members} member${roleCounts.members !== 1 ? "s" : ""}`)
    return parts.length > 0 ? ` (${parts.join(", ")})` : ""
  }, [roleCounts])

  const filteredMembers = useMemo(() => {
    let result = members

    if (roleFilter !== "ALL") {
      result = result.filter((m) => {
        if (roleFilter === "OWNER") return m.isOwner
        if (roleFilter === "ADMIN") return m.role === "ADMIN" && !m.isOwner
        return m.role === "MEMBER" || (!m.role && !m.isOwner)
      })
    }

    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase()
      result = result.filter(
        (m) => (m.name && m.name.toLowerCase().includes(query)) || m.email.toLowerCase().includes(query),
      )
    }

    return result
  }, [members, roleFilter, searchQuery])

  // ── Bulk selection helpers ──────────────────────────────────────────────
  const selectableMembers = useMemo(
    () => filteredMembers.filter((m) => !m.isOwner),
    [filteredMembers],
  )

  const allSelected = selectableMembers.length > 0 && selectableMembers.every((m) => selected.has(m.userId))
  const someSelected = selectableMembers.some((m) => selected.has(m.userId)) && !allSelected

  const toggleAll = () => {
    if (allSelected) {
      setSelected(new Set())
    } else {
      setSelected(new Set(selectableMembers.map((m) => m.userId)))
    }
  }

  const toggleOne = (userId: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(userId)) next.delete(userId)
      else next.add(userId)
      return next
    })
  }

  // ── Bulk actions ──────────────────────────────────────────────────────
  const bulkActions = useMemo((): BulkAction[] => {
    const invalidate = () => {
      queryClient.invalidateQueries({ queryKey: ["team", teamId] })
    }

    return [
      {
        key: "remove",
        label: "Remove Members",
        icon: <UserMinus className="h-4 w-4" />,
        variant: "destructive",
        confirm: {
          title: "Remove selected members?",
          description: "The selected members will lose access to all team resources. This cannot be undone.",
        },
        onExecute: async (ids) => {
          const errors: string[] = []
          for (const userId of ids) {
            const member = members.find((m) => m.userId === userId)
            if (!member) continue
            try {
              const response = await removeMemberFromTeam({
                path: { team_id: teamId },
                body: { userName: member.email },
              })
              if (response.error) throw new Error(response.error.detail || "Failed")
            } catch {
              errors.push(userId)
            }
          }
          invalidate()
          if (errors.length > 0) {
            toast.error(`Failed to remove ${errors.length} of ${ids.length} member${ids.length === 1 ? "" : "s"}`)
          } else {
            toast.success(`Removed ${ids.length} member${ids.length === 1 ? "" : "s"}`)
          }
        },
      },
      {
        key: "role-admin",
        label: "Set Admin",
        icon: <Shield className="h-4 w-4" />,
        variant: "outline",
        onExecute: async (ids) => {
          const errors: string[] = []
          for (const userId of ids) {
            try {
              const response = await updateTeamMember({
                path: { team_id: teamId, user_id: userId },
                body: { role: "ADMIN" },
              })
              if (response.error) throw new Error(response.error.detail || "Failed")
            } catch {
              errors.push(userId)
            }
          }
          invalidate()
          if (errors.length > 0) {
            toast.error(`Failed to update ${errors.length} of ${ids.length} member${ids.length === 1 ? "" : "s"}`)
          } else {
            toast.success(`Updated ${ids.length} member${ids.length === 1 ? "" : "s"} to Admin`)
          }
        },
      },
      {
        key: "role-member",
        label: "Set Member",
        icon: <User className="h-4 w-4" />,
        variant: "outline",
        onExecute: async (ids) => {
          const errors: string[] = []
          for (const userId of ids) {
            try {
              const response = await updateTeamMember({
                path: { team_id: teamId, user_id: userId },
                body: { role: "MEMBER" },
              })
              if (response.error) throw new Error(response.error.detail || "Failed")
            } catch {
              errors.push(userId)
            }
          }
          invalidate()
          if (errors.length > 0) {
            toast.error(`Failed to update ${errors.length} of ${ids.length} member${ids.length === 1 ? "" : "s"}`)
          } else {
            toast.success(`Updated ${ids.length} member${ids.length === 1 ? "" : "s"} to Member`)
          }
        },
      },
    ]
  }, [members, queryClient, teamId])

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

  const roleFilterButtons: { label: string; value: RoleFilter }[] = [
    { label: "All", value: "ALL" },
    { label: "Owners", value: "OWNER" },
    { label: "Admins", value: "ADMIN" },
    { label: "Members", value: "MEMBER" },
  ]

  return (
    <div className="space-y-6">
      <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <div className="space-y-1.5">
            <CardTitle>Members</CardTitle>
            <CardDescription>
              {members.length} member{members.length !== 1 ? "s" : ""} in this team{roleCountDescription}
            </CardDescription>
          </div>
          {canManageMembers && <InviteMemberDialog teamId={teamId} />}
        </CardHeader>
        <CardContent className="space-y-3">
          {/* Role filter buttons and select-all */}
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-1.5">
              {roleFilterButtons.map((btn) => (
                <Button
                  key={btn.value}
                  variant={roleFilter === btn.value ? "secondary" : "ghost"}
                  size="sm"
                  className="h-7 px-2.5 text-xs"
                  onClick={() => setRoleFilter(btn.value)}
                >
                  {btn.label}
                </Button>
              ))}
            </div>
            {canManageMembers && selectableMembers.length > 0 && (
              <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer select-none">
                <Checkbox
                  checked={allSelected}
                  indeterminate={someSelected}
                  onChange={toggleAll}
                  aria-label="Select all members"
                />
                Select all
              </label>
            )}
          </div>

          {/* Search input - only show when 5+ members */}
          {members.length >= 5 && (
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search by name or email..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="h-8 pl-8 text-sm"
              />
            </div>
          )}

          {/* Member list */}
          <div className="space-y-2">
            {filteredMembers.map((member: TeamMember) => {
              const isSelf = member.userId === user?.id
              const colorClass = getMemberColor(member.email)
              const isSelected = selected.has(member.userId)
              const canSelect = canManageMembers && !member.isOwner

              return (
                <div
                  key={member.id}
                  className={`flex items-center justify-between rounded-xl border p-3 transition-colors ${isSelected ? "border-primary/40 bg-primary/5" : isSelf ? "border-primary/30 bg-primary/5" : "border-border/60 bg-background/60 hover:bg-muted/30"}`}
                >
                  <div className="flex items-center gap-3">
                    {canSelect && (
                      <Checkbox
                        checked={isSelected}
                        onChange={() => toggleOne(member.userId)}
                        aria-label={`Select ${member.name ?? member.email}`}
                      />
                    )}
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
            {filteredMembers.length === 0 && members.length > 0 && (
              <div className="py-8 text-center text-sm text-muted-foreground">No members match the current filters.</div>
            )}
            {members.length === 0 && <div className="py-8 text-center text-sm text-muted-foreground">No members yet. Invite someone to get started.</div>}
          </div>
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
                      Invited as {invitation.role.toLowerCase()} &middot; {formatRelativeTimeShort(invitation.createdAt)}
                    </p>
                  </div>
                </div>
                {canManageMembers && (
                  <div className="flex items-center gap-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 gap-1 px-2 text-xs text-muted-foreground hover:text-foreground"
                      onClick={() => {
                        toast.info("Invitation resent", {
                          description: `A new invitation has been sent to ${invitation.email}.`,
                        })
                      }}
                    >
                      <RotateCw className="h-3.5 w-3.5" />
                      Resend
                    </Button>
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
                  </div>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Remove Member Confirmation AlertDialog */}
      <AlertDialog open={!!removeMember} onOpenChange={(open) => !open && setRemoveMember(null)}>
        <AlertDialogContent className="sm:max-w-md">
          <AlertDialogHeader>
            <div className="flex items-center gap-2">
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-destructive/10">
                <AlertTriangle className="h-5 w-5 text-destructive" />
              </div>
              <AlertDialogTitle>Remove member</AlertDialogTitle>
            </div>
            <AlertDialogDescription>
              Are you sure you want to remove <strong>{removeMember?.name ?? removeMember?.email}</strong> from this team? They will lose access to all team resources.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <Separator />
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setRemoveMember(null)}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              className={buttonDestructiveClass}
              disabled={removeMemberMutation.isPending}
              onClick={() => removeMember && removeMemberMutation.mutate(removeMember.email)}
            >
              {removeMemberMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Removing...
                </>
              ) : (
                "Remove member"
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {canManageMembers && (
        <BulkActionBar
          selectedCount={selected.size}
          selectedIds={Array.from(selected)}
          onClearSelection={() => setSelected(new Set())}
          actions={bulkActions}
        />
      )}
    </div>
  )
}

const buttonDestructiveClass = "bg-destructive text-white hover:bg-destructive/90"
