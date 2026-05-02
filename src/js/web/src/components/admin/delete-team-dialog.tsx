import { useCallback, useState } from "react"
import { AlertTriangle, Loader2 } from "lucide-react"
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
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useAdminDeleteTeam } from "@/lib/api/hooks/admin"

interface DeleteTeamDialogProps {
  teamId: string
  teamName: string
  open: boolean
  onOpenChange: (open: boolean) => void
  onDeleted?: () => void
}

export function DeleteTeamDialog({ teamId, teamName, open, onOpenChange, onDeleted }: DeleteTeamDialogProps) {
  const [confirmation, setConfirmation] = useState("")
  const deleteTeam = useAdminDeleteTeam()

  const confirmed = confirmation === teamName

  const restoreFocus = useCallback(() => {
    setTimeout(() => {
      const searchInput = document.querySelector<HTMLInputElement>('input[placeholder*="Search"]')
      if (searchInput) {
        searchInput.focus()
      }
    }, 0)
  }, [])

  const handleDelete = () => {
    if (!confirmed) return
    deleteTeam.mutate(teamId, {
      onSuccess: () => {
        setConfirmation("")
        onOpenChange(false)
        restoreFocus()
        onDeleted?.()
      },
    })
  }

  const handleOpenChange = (nextOpen: boolean) => {
    if (!nextOpen) {
      setConfirmation("")
    }
    onOpenChange(nextOpen)
  }

  return (
    <AlertDialog open={open} onOpenChange={handleOpenChange}>
      <AlertDialogContent onInteractOutside={(e) => e.preventDefault()}>
        {/* Red-tinted header */}
        <div className="-mx-6 -mt-6 rounded-t-lg bg-destructive/10 px-6 pt-6 pb-4">
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="h-5 w-5" />
              Delete Team
            </AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete <span className="font-semibold">{teamName}</span>? This action cannot be
              undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
        </div>

        {/* Consequences summary */}
        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <p className="text-sm font-medium">The following will be permanently removed:</p>
            <ul className="space-y-1 text-sm text-muted-foreground">
              <li className="flex items-start gap-2">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-destructive" />
                Members will be removed from the team
              </li>
              <li className="flex items-start gap-2">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-destructive" />
                Invitations will be cancelled
              </li>
              <li className="flex items-start gap-2">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-destructive" />
                Team permissions will be revoked
              </li>
            </ul>
          </div>

          {/* Type-to-confirm */}
          <div className="space-y-2">
            <Label htmlFor="delete-confirm">
              Type <span className="font-semibold">{teamName}</span> to confirm
            </Label>
            <Input
              id="delete-confirm"
              value={confirmation}
              onChange={(e) => setConfirmation(e.target.value)}
              placeholder={teamName}
              autoComplete="off"
            />
          </div>
        </div>

        <AlertDialogFooter>
          <AlertDialogCancel onClick={() => handleOpenChange(false)} disabled={deleteTeam.isPending}>
            Cancel
          </AlertDialogCancel>
          <AlertDialogAction
            onClick={handleDelete}
            disabled={!confirmed || deleteTeam.isPending}
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
          >
            {deleteTeam.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {deleteTeam.isPending ? "Deleting..." : "Delete team"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
