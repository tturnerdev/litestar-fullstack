import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Loader2, ShieldCheck, User } from "lucide-react"
import { useMemo, useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Label } from "@/components/ui/label"
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
      setSelectedTeamId("")
      setSelectedRole("MEMBER")
      onOpenChange(false)
    },
    onError: (error) => {
      toast.error("Unable to add user to team", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })

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
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Join Team</DialogTitle>
          <DialogDescription>
            Add {userName} to a team. Select a team and role below.
          </DialogDescription>
        </DialogHeader>

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
              <Label>Team</Label>
              <Select value={selectedTeamId} onValueChange={setSelectedTeamId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a team..." />
                </SelectTrigger>
                <SelectContent>
                  {availableTeams.map((team) => (
                    <SelectItem key={team.id} value={team.id}>
                      {team.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Role</Label>
              <Select value={selectedRole} onValueChange={(v) => setSelectedRole(v as TeamRoles)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {roleOptions.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      <div className="flex items-center gap-2">
                        <option.icon className="h-4 w-4 text-muted-foreground" />
                        <div className="flex flex-col">
                          <span>{option.label}</span>
                          <span className="text-xs text-muted-foreground">{option.description}</span>
                        </div>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
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
      </DialogContent>
    </Dialog>
  )
}
