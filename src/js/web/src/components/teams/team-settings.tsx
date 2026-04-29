import { zodResolver } from "@hookform/resolvers/zod"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { Loader2, Save, Trash2 } from "lucide-react"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { toast } from "sonner"
import { z } from "zod"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"
import { Textarea } from "@/components/ui/textarea"
import { deleteTeam, type Team, updateTeam } from "@/lib/generated/api"

const teamSettingsSchema = z.object({
  name: z.string().min(1, "Team name is required").max(100, "Team name must be under 100 characters"),
  description: z.string().max(500, "Description must be under 500 characters").optional(),
})

type TeamSettingsFormData = z.infer<typeof teamSettingsSchema>

interface TeamSettingsProps {
  team: Team
  teamId: string
  isOwner: boolean
}

export function TeamSettings({ team, teamId, isOwner }: TeamSettingsProps) {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [deleteConfirmation, setDeleteConfirmation] = useState("")

  const form = useForm<TeamSettingsFormData>({
    resolver: zodResolver(teamSettingsSchema),
    defaultValues: {
      name: team.name,
      description: team.description ?? "",
    },
  })

  const updateMutation = useMutation({
    mutationFn: async (data: TeamSettingsFormData) => {
      const response = await updateTeam({
        path: { team_id: teamId },
        body: {
          name: data.name,
          description: data.description || null,
        },
      })
      if (response.error) {
        throw new Error(response.error.detail || "Failed to update team")
      }
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["team", teamId] })
      queryClient.invalidateQueries({ queryKey: ["teams"] })
      toast.success("Team updated", {
        description: "Your changes have been saved.",
      })
    },
    onError: (error: Error) => {
      toast.error("Failed to update team", {
        description: error.message,
      })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async () => {
      const response = await deleteTeam({
        path: { team_id: teamId },
      })
      if (response.error) {
        throw new Error(response.error.detail || "Failed to delete team")
      }
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["teams"] })
      toast.success("Team deleted", {
        description: `"${team.name}" has been permanently deleted.`,
      })
      navigate({ to: "/teams" })
    },
    onError: (error: Error) => {
      toast.error("Failed to delete team", {
        description: error.message,
      })
    },
  })

  const isDirty = form.formState.isDirty
  const deleteConfirmed = deleteConfirmation === team.name

  return (
    <div className="space-y-6">
      {/* General Settings */}
      <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
        <CardHeader>
          <CardTitle>General</CardTitle>
          <CardDescription>Update the team name and description visible to all members.</CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit((data) => updateMutation.mutate(data))} className="space-y-5">
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Team name</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="Engineering" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="description"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Description</FormLabel>
                    <FormControl>
                      <Textarea {...field} placeholder="What does this team do?" className="resize-none" rows={3} />
                    </FormControl>
                    <FormDescription>A short summary of this team's purpose. Visible to all members.</FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <div className="flex justify-end">
                <Button type="submit" disabled={!isDirty || updateMutation.isPending} size="sm">
                  {updateMutation.isPending ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <Save className="mr-2 h-4 w-4" />
                  )}
                  {updateMutation.isPending ? "Saving..." : "Save changes"}
                </Button>
              </div>
            </form>
          </Form>
        </CardContent>
      </Card>

      {/* Danger Zone - Owner only */}
      {isOwner && (
        <Card className="border-destructive/30 bg-card/80 shadow-md">
          <CardHeader>
            <CardTitle className="text-destructive">Danger zone</CardTitle>
            <CardDescription>Irreversible and destructive actions for this team.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between rounded-lg border border-destructive/20 bg-destructive/5 p-4">
              <div className="space-y-1">
                <p className="font-medium text-sm">Delete this team</p>
                <p className="text-muted-foreground text-xs">
                  Once deleted, all team data, memberships, and associated resources will be permanently removed.
                </p>
              </div>
              <Button variant="destructive" size="sm" onClick={() => setDeleteDialogOpen(true)}>
                <Trash2 className="mr-2 h-4 w-4" />
                Delete team
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Delete team</DialogTitle>
            <DialogDescription>
              This action cannot be undone. This will permanently delete the <strong>{team.name}</strong> team, remove all member associations, and revoke any pending invitations.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <p className="text-sm text-muted-foreground">
              To confirm, type <strong className="text-foreground">{team.name}</strong> below:
            </p>
            <Input
              value={deleteConfirmation}
              onChange={(e) => setDeleteConfirmation(e.target.value)}
              placeholder={team.name}
              autoComplete="off"
            />
          </div>
          <Separator />
          <DialogFooter>
            <Button
              variant="ghost"
              onClick={() => {
                setDeleteDialogOpen(false)
                setDeleteConfirmation("")
              }}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={!deleteConfirmed || deleteMutation.isPending}
              onClick={() => deleteMutation.mutate()}
            >
              {deleteMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Deleting...
                </>
              ) : (
                "I understand, delete this team"
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
