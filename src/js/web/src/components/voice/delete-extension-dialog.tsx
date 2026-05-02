import { AlertTriangle, Loader2, Trash2 } from "lucide-react"
import { useCallback } from "react"
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
import { buttonVariants } from "@/components/ui/button"
import { useDeleteExtension } from "@/lib/api/hooks/voice"

interface DeleteExtensionDialogProps {
  extensionId: string
  extensionName: string
  extensionNumber: string
  open: boolean
  onOpenChange: (open: boolean) => void
  onDeleted?: () => void
}

export function DeleteExtensionDialog({ extensionId, extensionName, extensionNumber, open, onOpenChange, onDeleted }: DeleteExtensionDialogProps) {
  const deleteExtension = useDeleteExtension()

  const restoreFocus = useCallback(() => {
    setTimeout(() => {
      const searchInput = document.querySelector<HTMLInputElement>('input[placeholder*="Search"]')
      if (searchInput) {
        searchInput.focus()
      }
    }, 0)
  }, [])

  const handleDelete = () => {
    deleteExtension.mutate(extensionId, {
      onSuccess: () => {
        onOpenChange(false)
        restoreFocus()
        onDeleted?.()
      },
    })
  }

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            Delete Extension
          </AlertDialogTitle>
          <AlertDialogDescription>
            Are you sure you want to delete <span className="font-medium text-foreground">{extensionName}</span>
            {extensionNumber && (
              <>
                {" "}
                (Ext. <span className="font-mono text-foreground">{extensionNumber}</span>)
              </>
            )}
            ? This action cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div className="rounded-md border border-destructive/20 bg-destructive/5 px-4 py-3">
          <p className="mb-2 text-sm font-medium text-destructive">The following will be permanently removed:</p>
          <ul className="list-inside list-disc space-y-1 text-sm text-muted-foreground">
            <li>All call forwarding rules</li>
            <li>Voicemail settings and messages</li>
            <li>Do Not Disturb configuration</li>
          </ul>
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={() => onOpenChange(false)} disabled={deleteExtension.isPending}>
            Cancel
          </AlertDialogCancel>
          <AlertDialogAction className={buttonVariants({ variant: "destructive" })} onClick={handleDelete} disabled={deleteExtension.isPending}>
            {deleteExtension.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Trash2 className="mr-2 h-4 w-4" />}
            Delete Extension
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
