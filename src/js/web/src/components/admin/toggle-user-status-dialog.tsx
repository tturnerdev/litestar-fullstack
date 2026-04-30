import { ArrowRight, Loader2, UserCheck, UserX } from "lucide-react"
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
  userName?: string
  isActive: boolean
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function ToggleUserStatusDialog({ userId, userEmail, userName, isActive, open, onOpenChange }: ToggleUserStatusDialogProps) {
  const updateUser = useAdminUpdateUser(userId)

  const actionLabel = isActive ? "Deactivate" : "Activate"
  const StatusIcon = isActive ? UserX : UserCheck

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
          <div className={`-mx-6 -mt-6 mb-4 rounded-t-lg px-6 pb-4 pt-6 ${isActive ? "bg-red-500/5" : "bg-green-500/5"}`}>
            <AlertDialogTitle className="flex items-center gap-2">
              <StatusIcon className={`size-5 ${isActive ? "text-red-500" : "text-green-500"}`} />
              {actionLabel} user
            </AlertDialogTitle>
          </div>
          <AlertDialogDescription asChild>
            <div className="space-y-3 text-sm text-muted-foreground">
              <p>
                {isActive
                  ? "Are you sure you want to deactivate "
                  : "Are you sure you want to activate "}
                {userName && (
                  <span className="font-medium text-foreground">{userName}</span>
                )}
                {userName && " "}
                (<span className="font-medium text-foreground">{userEmail}</span>)?
              </p>

              {/* Status transition indicator */}
              <div className="flex items-center gap-2 rounded-md border bg-muted/50 px-3 py-2 text-sm">
                <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ${isActive ? "bg-green-500/10 text-green-600" : "bg-red-500/10 text-red-600"}`}>
                  {isActive ? "Active" : "Inactive"}
                </span>
                <ArrowRight className="size-3.5 text-muted-foreground" />
                <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ${isActive ? "bg-red-500/10 text-red-600" : "bg-green-500/10 text-green-600"}`}>
                  {isActive ? "Inactive" : "Active"}
                </span>
              </div>

              {/* Impact summary */}
              {isActive ? (
                <ul className="space-y-1.5 pl-1 text-sm text-muted-foreground">
                  <li className="flex items-start gap-2">
                    <span className="mt-1.5 size-1 shrink-0 rounded-full bg-red-400" />
                    User will be logged out of all sessions
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="mt-1.5 size-1 shrink-0 rounded-full bg-red-400" />
                    User cannot sign in
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="mt-1.5 size-1 shrink-0 rounded-full bg-muted-foreground" />
                    Team memberships preserved
                  </li>
                </ul>
              ) : (
                <ul className="space-y-1.5 pl-1 text-sm text-muted-foreground">
                  <li className="flex items-start gap-2">
                    <span className="mt-1.5 size-1 shrink-0 rounded-full bg-green-400" />
                    User will regain system access
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="mt-1.5 size-1 shrink-0 rounded-full bg-green-400" />
                    Existing team memberships will be restored
                  </li>
                </ul>
              )}
            </div>
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
            {updateUser.isPending && <Loader2 className="size-4 animate-spin" />}
            {updateUser.isPending ? `${actionLabel.slice(0, -1)}ing...` : `${actionLabel} user`}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
