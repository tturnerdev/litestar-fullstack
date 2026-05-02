import { AnimatePresence, motion } from "framer-motion"
import { Download, Loader2, ToggleLeft, ToggleRight, Trash2, X } from "lucide-react"
import { useState } from "react"
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

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BulkAction {
  /** Unique key for this action */
  key: string
  /** Button label */
  label: string
  /** Lucide icon element */
  icon?: React.ReactNode
  /** Button variant — destructive actions get a confirmation dialog */
  variant?: "default" | "destructive" | "outline" | "secondary"
  /** Confirmation prompt shown before executing destructive actions */
  confirm?: {
    title: string
    description: string
  }
  /** Async handler executed when the action is confirmed */
  onExecute: (selectedIds: string[]) => Promise<void>
}

interface BulkActionBarProps {
  /** Number of selected items */
  selectedCount: number
  /** The selected IDs, passed through to action handlers */
  selectedIds: string[]
  /** Callback to deselect everything */
  onClearSelection: () => void
  /** Available bulk actions */
  actions: BulkAction[]
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function BulkActionBar({ selectedCount, selectedIds, onClearSelection, actions }: BulkActionBarProps) {
  const [pendingAction, setPendingAction] = useState<BulkAction | null>(null)
  const [executing, setExecuting] = useState(false)
  const [progress, setProgress] = useState("")

  const visible = selectedCount > 0

  async function handleExecute(action: BulkAction) {
    setExecuting(true)
    setProgress(`Processing ${selectedIds.length} item${selectedIds.length === 1 ? "" : "s"}...`)
    try {
      await action.onExecute(selectedIds)
      onClearSelection()
    } finally {
      setExecuting(false)
      setProgress("")
      setPendingAction(null)
      // After bulk action completes, the selected rows may be gone.
      // Restore focus to the search input or first interactive element on the page.
      setTimeout(() => {
        const searchInput = document.querySelector<HTMLInputElement>('input[placeholder*="Search"]')
        if (searchInput) {
          searchInput.focus()
        }
      }, 0)
    }
  }

  function handleActionClick(action: BulkAction) {
    if (action.confirm) {
      setPendingAction(action)
    } else {
      handleExecute(action)
    }
  }

  return (
    <>
      <AnimatePresence>
        {visible && (
          <motion.div
            initial={{ y: 80, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: 80, opacity: 0 }}
            transition={{ type: "spring", stiffness: 400, damping: 30 }}
            className="fixed inset-x-0 bottom-0 z-50 flex items-center justify-between border-t bg-background/95 px-6 py-3 shadow-lg backdrop-blur supports-[backdrop-filter]:bg-background/80"
          >
            <div className="flex items-center gap-3">
              <span className="text-sm font-medium">
                {selectedCount} item{selectedCount === 1 ? "" : "s"} selected
              </span>
              <Button variant="ghost" size="sm" onClick={onClearSelection} disabled={executing}>
                <X className="mr-1 h-3 w-3" />
                Clear
              </Button>
            </div>

            {executing ? (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" />
                {progress}
              </div>
            ) : (
              <div className="flex items-center gap-2">
                {actions.map((action) => (
                  <Button key={action.key} variant={action.variant ?? "outline"} size="sm" onClick={() => handleActionClick(action)} disabled={executing}>
                    {action.icon}
                    {action.label}
                  </Button>
                ))}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Confirmation dialog for destructive actions */}
      <AlertDialog open={pendingAction !== null} onOpenChange={(open) => !open && !executing && setPendingAction(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{pendingAction?.confirm?.title ?? "Confirm"}</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete {selectedIds.length} {selectedIds.length === 1 ? "item" : "items"}. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setPendingAction(null)} disabled={executing}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => pendingAction && handleExecute(pendingAction)}
              disabled={executing}
              className={pendingAction?.variant === "destructive" ? "bg-destructive text-white hover:bg-destructive/90" : ""}
            >
              {executing && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete {selectedIds.length} {selectedIds.length === 1 ? "item" : "items"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// ---------------------------------------------------------------------------
// Pre-built action helpers
// ---------------------------------------------------------------------------

/**
 * Creates a bulk delete action with progress reporting.
 *
 * @param deleteFn     - Function that deletes a single item by ID.
 * @param invalidateFn - Called once after all deletes complete.
 */
export function createBulkDeleteAction(deleteFn: (id: string) => Promise<void>, invalidateFn: () => void, opts?: { label?: string }): BulkAction {
  return {
    key: "delete",
    label: opts?.label ?? "Delete Selected",
    icon: <Trash2 className="h-4 w-4" />,
    variant: "destructive",
    confirm: {
      title: "Delete selected items?",
      description: "This action cannot be undone. All selected items will be permanently deleted.",
    },
    onExecute: async (ids) => {
      const errors: string[] = []
      for (let i = 0; i < ids.length; i++) {
        try {
          await deleteFn(ids[i])
        } catch (e) {
          errors.push(ids[i])
        }
      }
      invalidateFn()
      if (errors.length > 0) {
        const { toast } = await import("sonner")
        toast.error(`Failed to delete ${errors.length} of ${ids.length} items`)
      } else {
        const { toast } = await import("sonner")
        toast.success(`Deleted ${ids.length} item${ids.length === 1 ? "" : "s"}`)
      }
    },
  }
}

/**
 * Creates a CSV export action for selected items.
 *
 * @param filename - Base filename (without .csv extension).
 * @param headers  - Column definitions for the CSV.
 * @param getItems - Function that returns items matching the given IDs.
 */
export function createExportAction<T>(filename: string, headers: Array<{ label: string; accessor: (row: T) => unknown }>, getItems: (ids: string[]) => T[]): BulkAction {
  return {
    key: "export",
    label: "Export Selected",
    icon: <Download className="h-4 w-4" />,
    variant: "outline",
    onExecute: async (ids) => {
      const { exportToCsv } = await import("@/lib/csv-export")
      const items = getItems(ids)
      exportToCsv(filename, headers, items)
      const { toast } = await import("sonner")
      toast.success(`Exported ${items.length} item${items.length === 1 ? "" : "s"}`)
    },
  }
}

/**
 * Creates a pair of bulk enable/disable toggle actions.
 *
 * @param updateFn     - Function that updates a single item by ID with a boolean flag.
 * @param invalidateFn - Called once after all updates complete.
 * @param opts         - Optional overrides for labels and the payload field name.
 */
export function createBulkToggleActions(
  updateFn: (id: string, enabled: boolean) => Promise<void>,
  invalidateFn: () => void,
  opts?: { enableLabel?: string; disableLabel?: string; entityName?: string },
): [BulkAction, BulkAction] {
  const entityName = opts?.entityName ?? "item"

  const enableAction: BulkAction = {
    key: "enable",
    label: opts?.enableLabel ?? "Enable Selected",
    icon: <ToggleRight className="h-4 w-4" />,
    variant: "outline",
    onExecute: async (ids) => {
      const errors: string[] = []
      for (const id of ids) {
        try {
          await updateFn(id, true)
        } catch {
          errors.push(id)
        }
      }
      invalidateFn()
      const { toast } = await import("sonner")
      if (errors.length > 0) {
        toast.error(`Failed to enable ${errors.length} of ${ids.length} ${entityName}s`)
      } else {
        toast.success(`Enabled ${ids.length} ${entityName}${ids.length === 1 ? "" : "s"}`)
      }
    },
  }

  const disableAction: BulkAction = {
    key: "disable",
    label: opts?.disableLabel ?? "Disable Selected",
    icon: <ToggleLeft className="h-4 w-4" />,
    variant: "outline",
    onExecute: async (ids) => {
      const errors: string[] = []
      for (const id of ids) {
        try {
          await updateFn(id, false)
        } catch {
          errors.push(id)
        }
      }
      invalidateFn()
      const { toast } = await import("sonner")
      if (errors.length > 0) {
        toast.error(`Failed to disable ${errors.length} of ${ids.length} ${entityName}s`)
      } else {
        toast.success(`Disabled ${ids.length} ${entityName}${ids.length === 1 ? "" : "s"}`)
      }
    },
  }

  return [enableAction, disableAction]
}
