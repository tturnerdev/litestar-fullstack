import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { useAdminDeleteTeam } from "@/lib/api/hooks/admin"

interface DeleteTeamDialogProps {
  teamId: string
  teamName: string
  open: boolean
  onOpenChange: (open: boolean) => void
  onDeleted?: () => void
}

export function DeleteTeamDialog({ teamId, teamName, open, onOpenChange, onDeleted }: DeleteTeamDialogProps) {
  const deleteTeam = useAdminDeleteTeam()

  const handleDelete = () => {
    deleteTeam.mutate(teamId, {
      onSuccess: () => {
        onOpenChange(false)
        onDeleted?.()
      },
    })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete Team</DialogTitle>
          <DialogDescription>
            Are you sure you want to delete <span className="font-semibold">{teamName}</span>? This action cannot be undone. All team data,
            memberships, and invitations will be permanently removed.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={handleDelete} disabled={deleteTeam.isPending}>
            {deleteTeam.isPending ? "Deleting..." : "Delete team"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
