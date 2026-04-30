import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { CheckCircle2, Loader2, ShieldCheck, User, UserPlus } from "lucide-react"
import { useCallback, useEffect, useMemo, useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { useAdminUser } from "@/lib/api/hooks/admin"
import {
  addMemberToTeam,
  listTeams,
  type Team,
  type TeamRoles,
} from "@/lib/generated/api"

interface JoinTeamDialogProps {
  userId: string
  userName: string
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function JoinTeamDialog({ userId, userName, open, onOpenChange }: JoinTeamDialogProps) {
  const [selectedTeamId, setSelectedTeamId] = useState("")
  const [selectedRole, setSelectedRole] = useState<TeamRoles>("MEMBER")
  const [showSuccess, setShowSuccess] = useState(false)
  const queryClient = useQueryClient()

  const { data: user } = useAdminUser(userId)

  const { data: teamsData, isLoading: teamsLoading } = useQuery({
    queryKey: ["teams", "all"],
    queryFn: async () => {
      const response = await listTeams({ query: { pageSize: 500 } })
      return response.data as { items?: Team[] }
    },
    enabled: open,
  })

  const availableTeams = useMemo(() => {
    const allTeams = teamsData?.items ?? []
    const memberTeamIds = new Set((user?.teams ?? []).map((t) => t.teamId))
    return allTeams.filter((team) => !memberTeamIds.has(team.id))
  }, [teamsData, user?.teams])

  const handleClose = useCallback(
    (value: boolean) => {
      if (!showSuccess) {
        onOpenChange(value)
      }
    },
    [showSuccess, onOpenChange],
  )

  const joinMutation = useMutation({
    mutationFn: async () => {
      await addMemberToTeam({
        path: { team_id: selectedTeamId },
        body: { userName },
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "users"] })
      queryClient.invalidateQueries({ queryKey: ["admin", "user", userId] })
      toast.success("User added to team")
      setShowSuccess(true)
    },
    onError: (error) => {
      toast.error("Unable to add user to team", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })

  useEffect(() => {
    if (showSuccess) {
      const timer = setTimeout(() => {
        setShowSuccess(false)
        setSelectedTeamId("")
        setSelectedRole("MEMBER")
        onOpenChange(false)
      }, 800)
      return () => clearTimeout(timer)
    }
  }, [showSuccess, onOpenChange])

  const handleJoin = () => {
    if (selectedTeamId) {
      joinMutation.mutate()
    }
  }

  const roleOptions = [
    {
      value: "MEMBER" as const,
      label: "Member",
      description: "Can view and collaborate on team content",
      icon: User,
    },
    {
      value: "ADMIN" as const,
      label: "Admin",
      description: "Can manage team settings and members",
      icon: ShieldCheck,
    },
  ]

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-md">
        {showSuccess ? (
          <div className="flex flex-col items-center justify-center py-12">
            <div className="rounded-full bg-green-100 p-3 dark:bg-green-900/30">
              <CheckCircle2 className="h-8 w-8 text-green-600 dark:text-green-400" />
            </div>
            <p className="mt-3 text-sm font-medium">Added to team successfully</p>
          </div>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <UserPlus className="h-5 w-5 text-muted-foreground" />
                Join Team
              </DialogTitle>
              <DialogDescription>
                Add {userName} to a team. Select a team and role below.
              </DialogDescription>
            </DialogHeader>

            <div className="rounded-lg bg-muted/50 p-3">
              <div className="flex items-center gap-2">
                <User className="h-4 w-4 text-muted-foreground" />
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{user?.name ?? userName}</p>
                  {user?.email && (
                    <p className="truncate text-xs text-muted-foreground">{user.email}</p>
                  )}
                </div>
              </div>
            </div>

            {teamsLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : availableTeams.length === 0 ? (
              <p className="py-4 text-sm text-muted-foreground">
                This user is already a member of all available teams.
              </p>
            ) : (
              <div className="space-y-4">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label>Team</Label>
                    <span className="text-xs text-muted-foreground">
                      {availableTeams.length} {availableTeams.length === 1 ? "team" : "teams"} available
                    </span>
                  </div>
                  <Select value={selectedTeamId} onValueChange={setSelectedTeamId}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select a team..." />
                    </SelectTrigger>
                    <SelectContent>
                      {availableTeams.map((team) => (
                        <SelectItem key={team.id} value={team.id}>
                          <div className="flex flex-col">
                            <span>{team.name}</span>
                            {team.description && (
                              <span className="text-xs text-muted-foreground">
                                {team.description.length > 60
                                  ? `${team.description.slice(0, 60)}...`
                                  : team.description}
                              </span>
                            )}
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <Separator />

                <div className="space-y-2">
                  <Label>Role</Label>
                  <div className="grid grid-cols-2 gap-2">
                    {roleOptions.map((option) => {
                      const isSelected = selectedRole === option.value
                      return (
                        <button
                          key={option.value}
                          type="button"
                          onClick={() => setSelectedRole(option.value)}
                          className={`flex flex-col items-start gap-1 rounded-lg border p-3 text-left transition-colors ${
                            isSelected
                              ? "border-primary bg-primary/5"
                              : "border-border hover:border-muted-foreground/30 hover:bg-muted/30"
                          }`}
                        >
                          <div className="flex items-center gap-2">
                            <option.icon
                              className={`h-4 w-4 ${isSelected ? "text-primary" : "text-muted-foreground"}`}
                            />
                            <span className="text-sm font-medium">{option.label}</span>
                          </div>
                          <span className="text-xs text-muted-foreground">{option.description}</span>
                        </button>
                      )
                    })}
                  </div>
                </div>
              </div>
            )}

            <DialogFooter>
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button
                onClick={handleJoin}
                disabled={!selectedTeamId || joinMutation.isPending}
              >
                {joinMutation.isPending ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Adding...
                  </>
                ) : (
                  "Join"
                )}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}
