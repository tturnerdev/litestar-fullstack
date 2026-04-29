import { useNavigate } from "@tanstack/react-router"
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

  function handleDelete() {
    deleteUser.mutate(userId, {
      onSuccess: () => {
        onOpenChange(false)
        if (navigateOnDelete) {
          navigate({ to: "/admin/users" })
        }
      },
    })
  }

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete user</AlertDialogTitle>
          <AlertDialogDescription>
            Are you sure you want to permanently delete <span className="font-medium text-foreground">{userEmail}</span>? This action cannot be undone. All data associated with this user will be removed.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={() => onOpenChange(false)} disabled={deleteUser.isPending}>
            Cancel
          </AlertDialogCancel>
          <AlertDialogAction
            onClick={handleDelete}
            disabled={deleteUser.isPending}
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
          >
            {deleteUser.isPending ? "Deleting..." : "Delete user"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
