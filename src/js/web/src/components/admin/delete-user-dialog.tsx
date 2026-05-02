import { useNavigate } from "@tanstack/react-router"
import { AlertTriangle, Loader2, ShieldAlert } from "lucide-react"
import { useCallback, useState } from "react"
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
import { useAdminDeleteUser } from "@/lib/api/hooks/admin"

interface DeleteUserDialogProps {
  userId: string
  userEmail: string
  open: boolean
  onOpenChange: (open: boolean) => void
  /** If true, navigate to user list after successful deletion */
  navigateOnDelete?: boolean
}

export function DeleteUserDialog({ userId, userEmail, open, onOpenChange, navigateOnDelete = false }: DeleteUserDialogProps) {
  const deleteUser = useAdminDeleteUser()
  const navigate = useNavigate()
  const [confirmText, setConfirmText] = useState("")

  const isConfirmed = confirmText === userEmail

  const restoreFocus = useCallback(() => {
    setTimeout(() => {
      const searchInput = document.querySelector<HTMLInputElement>('input[placeholder*="Search"]')
      if (searchInput) {
        searchInput.focus()
      }
    }, 0)
  }, [])

  function handleDelete() {
    if (!isConfirmed) return
    deleteUser.mutate(userId, {
      onSuccess: () => {
        setConfirmText("")
        onOpenChange(false)
        if (navigateOnDelete) {
          navigate({ to: "/admin/users" })
        } else {
          restoreFocus()
        }
      },
    })
  }

  function handleOpenChange(nextOpen: boolean) {
    if (!nextOpen) {
      setConfirmText("")
    }
    onOpenChange(nextOpen)
  }

  return (
    <AlertDialog open={open} onOpenChange={handleOpenChange}>
      <AlertDialogContent>
        <div className="rounded-t-lg bg-destructive/10 px-6 py-4 -mx-6 -mt-6 mb-2">
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="size-5" />
              Delete user
            </AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to permanently delete <span className="font-medium text-foreground">{userEmail}</span>?
            </AlertDialogDescription>
          </AlertDialogHeader>
        </div>

        <div className="space-y-4">
          <div className="rounded-md border border-destructive/20 bg-destructive/5 p-3">
            <p className="mb-2 text-sm font-medium">This will permanently remove:</p>
            <ul className="list-disc pl-5 space-y-1 text-sm text-muted-foreground">
              <li>Account data</li>
              <li>Team memberships</li>
              <li>Session tokens</li>
              <li>OAuth connections</li>
            </ul>
          </div>

          <div className="flex items-start gap-2 rounded-md border border-border bg-muted/30 p-3">
            <ShieldAlert className="mt-0.5 size-4 shrink-0 text-destructive" />
            <p className="text-sm text-muted-foreground">
              This action is <span className="font-medium text-foreground">permanent and irreversible</span>. The user will lose all access and their data cannot be recovered.
            </p>
          </div>

          <div className="grid gap-2">
            <label htmlFor="delete-confirm-input" className="text-sm font-medium">
              Type <span className="font-mono text-destructive">{userEmail}</span> to confirm
            </label>
            <Input
              id="delete-confirm-input"
              placeholder={`Type ${userEmail} to confirm`}
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
        </div>

        <AlertDialogFooter>
          <AlertDialogCancel onClick={() => handleOpenChange(false)} disabled={deleteUser.isPending}>
            Cancel
          </AlertDialogCancel>
          <AlertDialogAction onClick={handleDelete} disabled={!isConfirmed || deleteUser.isPending} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
            {deleteUser.isPending ? (
              <>
                <Loader2 className="size-4 animate-spin" />
                Deleting...
              </>
            ) : (
              "Delete user"
            )}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
