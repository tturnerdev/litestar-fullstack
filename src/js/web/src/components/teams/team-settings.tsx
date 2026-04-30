import { zodResolver } from "@hookform/resolvers/zod"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { AlertTriangle, Loader2, Save, Settings, Trash2, Undo2 } from "lucide-react"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { toast } from "sonner"
import { z } from "zod"
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
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"
import { Textarea } from "@/components/ui/textarea"
import { deleteTeam, type Team, updateTeam } from "@/lib/generated/api"

const NAME_MAX = 100
const DESCRIPTION_MAX = 500

const teamSettingsSchema = z.object({
  name: z.string().min(1, "Team name is required").max(NAME_MAX, `Team name must be under ${NAME_MAX} characters`),
  description: z.string().max(DESCRIPTION_MAX, `Description must be under ${DESCRIPTION_MAX} characters`).optional(),
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

  const nameValue = form.watch("name") ?? ""
  const descriptionValue = form.watch("description") ?? ""

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
      form.reset(form.getValues())
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
  const memberCount = team.members?.length ?? 0

  return (
    <div className="space-y-6">
      {/* Unsaved changes banner */}
      {isDirty && (
        <div className="flex items-center justify-between rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2.5">
          <p className="text-sm font-medium text-amber-700 dark:text-amber-400">You have unsaved changes</p>
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              className="h-7 gap-1.5 px-2.5 text-xs"
              onClick={() => form.reset()}
            >
              <Undo2 className="h-3.5 w-3.5" />
              Discard
            </Button>
            <Button
              size="sm"
              className="h-7 gap-1.5 px-2.5 text-xs"
              disabled={updateMutation.isPending}
              onClick={form.handleSubmit((data) => updateMutation.mutate(data))}
            >
              {updateMutation.isPending ? <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : <Save className="mr-1 h-3.5 w-3.5" />}
              Save
            </Button>
          </div>
        </div>
      )}

      {/* General Settings */}
      <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-4 w-4 text-muted-foreground" />
            General
          </CardTitle>
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
                    <div className="flex items-center justify-between">
                      <FormDescription>This is the display name shown across the platform</FormDescription>
                      <span className={`text-xs tabular-nums ${nameValue.length > NAME_MAX ? "text-destructive" : "text-muted-foreground"}`}>
                        {nameValue.length}/{NAME_MAX}
                      </span>
                    </div>
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
                    <div className="flex items-center justify-between">
                      <FormDescription>A short summary of this team's purpose. Visible to all members.</FormDescription>
                      <span className={`text-xs tabular-nums ${descriptionValue.length > DESCRIPTION_MAX ? "text-destructive" : "text-muted-foreground"}`}>
                        {descriptionValue.length}/{DESCRIPTION_MAX}
                      </span>
                    </div>
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
            <CardTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="h-4 w-4" />
              Danger zone
            </CardTitle>
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

      {/* Delete Confirmation AlertDialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent className="sm:max-w-md">
          <AlertDialogHeader>
            <div className="flex items-center gap-2">
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-destructive/10">
                <AlertTriangle className="h-5 w-5 text-destructive" />
              </div>
              <AlertDialogTitle>Delete team</AlertDialogTitle>
            </div>
            <AlertDialogDescription>
              This action cannot be undone. This will permanently delete the <strong>{team.name}</strong> team.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="rounded-lg bg-destructive/10 p-3 space-y-1.5">
            <p className="text-sm font-medium text-destructive">The following will happen:</p>
            <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground">
              <li>All {memberCount} member{memberCount !== 1 ? "s" : ""} will lose access</li>
              <li>Pending invitations will be revoked</li>
              <li>Team resources will be removed</li>
            </ul>
          </div>
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
          <AlertDialogFooter>
            <AlertDialogCancel
              onClick={() => {
                setDeleteDialogOpen(false)
                setDeleteConfirmation("")
              }}
            >
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-white hover:bg-destructive/90"
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
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
