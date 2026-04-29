import { useState } from "react"
import { useQueryClient } from "@tanstack/react-query"
import { AnimatePresence, motion } from "framer-motion"
import { ShieldCheck, ShieldOff, Trash2, X } from "lucide-react"
import { toast } from "sonner"
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
import { adminDeleteUser, adminUpdateUser } from "@/lib/generated/api"

type BulkAction = "activate" | "deactivate" | "delete"

interface UserBulkActionsProps {
  selectedIds: Set<string>
  onClearSelection: () => void
}

const actionConfig: Record<
  BulkAction,
  {
    label: string
    description: string
    icon: typeof Trash2
    variant: "default" | "destructive" | "outline"
  }
> = {
  activate: {
    label: "Activate Selected",
    description:
      "This will activate all selected users, allowing them to sign in and access the system.",
    icon: ShieldCheck,
    variant: "default",
  },
  deactivate: {
    label: "Deactivate Selected",
    description:
      "This will deactivate all selected users. They will no longer be able to sign in.",
    icon: ShieldOff,
    variant: "outline",
  },
  delete: {
    label: "Delete Selected",
    description:
      "This will permanently delete all selected users. This action cannot be undone.",
    icon: Trash2,
    variant: "destructive",
  },
}

export function UserBulkActions({
  selectedIds,
  onClearSelection,
}: UserBulkActionsProps) {
  const queryClient = useQueryClient()
  const [pendingAction, setPendingAction] = useState<BulkAction | null>(null)
  const [isProcessing, setIsProcessing] = useState(false)

  const count = selectedIds.size

  async function handleConfirm() {
    if (!pendingAction || count === 0) return
    setIsProcessing(true)

    const ids = Array.from(selectedIds)
    let succeeded = 0
    let failed = 0

    try {
      for (const id of ids) {
        try {
          if (pendingAction === "delete") {
            await adminDeleteUser({ path: { user_id: id } })
          } else {
            await adminUpdateUser({
              path: { user_id: id },
              body: { isActive: pendingAction === "activate" },
            })
          }
          succeeded++
        } catch {
          failed++
        }
      }

      // Invalidate admin user queries so the table refreshes
      await queryClient.invalidateQueries({ queryKey: ["admin", "users"] })

      if (failed === 0) {
        toast.success(`${actionConfig[pendingAction].label} completed`, {
          description: `Successfully processed ${succeeded} user${succeeded !== 1 ? "s" : ""}.`,
        })
      } else {
        toast.warning("Partially completed", {
          description: `${succeeded} succeeded, ${failed} failed.`,
        })
      }

      onClearSelection()
    } finally {
      setIsProcessing(false)
      setPendingAction(null)
    }
  }

  return (
    <>
      <AnimatePresence>
        {count > 0 && (
          <motion.div
            initial={{ y: 100, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: 100, opacity: 0 }}
            transition={{ type: "spring", damping: 25, stiffness: 300 }}
            className="fixed inset-x-0 bottom-6 z-50 mx-auto flex w-fit items-center gap-3 rounded-lg border bg-background px-4 py-3 shadow-lg"
          >
            <span className="text-sm font-medium tabular-nums">
              {count} selected
            </span>

            <div className="h-5 w-px bg-border" />

            {(Object.keys(actionConfig) as BulkAction[]).map((action) => {
              const config = actionConfig[action]
              const Icon = config.icon
              return (
                <Button
                  key={action}
                  variant={config.variant}
                  size="sm"
                  onClick={() => setPendingAction(action)}
                >
                  <Icon className="mr-1.5 size-3.5" />
                  {config.label}
                </Button>
              )
            })}

            <div className="h-5 w-px bg-border" />

            <Button variant="ghost" size="sm" onClick={onClearSelection}>
              <X className="mr-1.5 size-3.5" />
              Clear
            </Button>
          </motion.div>
        )}
      </AnimatePresence>

      <AlertDialog
        open={pendingAction !== null}
        onOpenChange={(open) => {
          if (!open) setPendingAction(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {pendingAction ? actionConfig[pendingAction].label : ""}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {pendingAction
                ? `${actionConfig[pendingAction].description} This will affect ${count} user${count !== 1 ? "s" : ""}.`
                : ""}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isProcessing}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleConfirm}
              disabled={isProcessing}
              className={
                pendingAction === "delete"
                  ? "bg-destructive text-white hover:bg-destructive/90"
                  : ""
              }
            >
              {isProcessing ? "Processing..." : "Confirm"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
