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
import { useAdminUpdateUser } from "@/lib/api/hooks/admin"

interface ToggleUserStatusDialogProps {
  userId: string
  userEmail: string
  isActive: boolean
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function ToggleUserStatusDialog({ userId, userEmail, isActive, open, onOpenChange }: ToggleUserStatusDialogProps) {
  const updateUser = useAdminUpdateUser(userId)

  const actionLabel = isActive ? "Deactivate" : "Activate"

  function handleToggle() {
    updateUser.mutate(
      { is_active: !isActive },
      {
        onSuccess: () => {
          onOpenChange(false)
        },
      },
    )
  }

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{actionLabel} user</AlertDialogTitle>
          <AlertDialogDescription>
            {isActive ? (
              <>
                Are you sure you want to deactivate <span className="font-medium text-foreground">{userEmail}</span>? They will lose access to the system until reactivated.
              </>
            ) : (
              <>
                Are you sure you want to activate <span className="font-medium text-foreground">{userEmail}</span>? They will regain access to the system.
              </>
            )}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={() => onOpenChange(false)} disabled={updateUser.isPending}>
            Cancel
          </AlertDialogCancel>
          <AlertDialogAction
            onClick={handleToggle}
            disabled={updateUser.isPending}
            className={isActive ? "bg-destructive text-destructive-foreground hover:bg-destructive/90" : ""}
          >
            {updateUser.isPending ? `${actionLabel.slice(0, -1)}ing...` : `${actionLabel} user`}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
