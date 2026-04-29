import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { useAdminUpdateTeam } from "@/lib/api/hooks/admin"

interface EditTeamDialogProps {
  teamId: string
  currentName: string
  currentDescription: string | null | undefined
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function EditTeamDialog({ teamId, currentName, currentDescription, open, onOpenChange }: EditTeamDialogProps) {
  const [name, setName] = useState(currentName)
  const [description, setDescription] = useState(currentDescription ?? "")
  const updateTeam = useAdminUpdateTeam(teamId)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    updateTeam.mutate(
      { name, description: description || null },
      {
        onSuccess: () => {
          onOpenChange(false)
        },
      },
    )
  }

  const handleOpenChange = (nextOpen: boolean) => {
    if (nextOpen) {
      setName(currentName)
      setDescription(currentDescription ?? "")
    }
    onOpenChange(nextOpen)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent>
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Edit Team</DialogTitle>
            <DialogDescription>Update the team name and description.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="team-name">Name</Label>
              <Input id="team-name" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <div className="space-y-2">
              <Label htmlFor="team-description">Description</Label>
              <Textarea
                id="team-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Optional team description"
                rows={3}
              />
            </div>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={updateTeam.isPending || !name.trim()}>
              {updateTeam.isPending ? "Saving..." : "Save changes"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
