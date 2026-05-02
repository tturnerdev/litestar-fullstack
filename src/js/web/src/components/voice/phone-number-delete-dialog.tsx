import { useCallback } from "react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { useDeletePhoneNumber } from "@/lib/api/hooks/voice"

interface PhoneNumberDeleteDialogProps {
  phoneNumberId: string
  phoneNumber: string
  open: boolean
  onOpenChange: (open: boolean) => void
  onDeleted?: () => void
}

export function PhoneNumberDeleteDialog({ phoneNumberId, phoneNumber, open, onOpenChange, onDeleted }: PhoneNumberDeleteDialogProps) {
  const deletePhoneNumber = useDeletePhoneNumber()

  const restoreFocus = useCallback(() => {
    setTimeout(() => {
      const searchInput = document.querySelector<HTMLInputElement>('input[placeholder*="Search"]')
      if (searchInput) {
        searchInput.focus()
      }
    }, 0)
  }, [])

  const handleDelete = () => {
    deletePhoneNumber.mutate(phoneNumberId, {
      onSuccess: () => {
        onOpenChange(false)
        restoreFocus()
        onDeleted?.()
      },
    })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete phone number</DialogTitle>
          <DialogDescription>
            Are you sure you want to delete <span className="font-medium text-foreground">{phoneNumber}</span>? This action cannot be undone. Any associated
            extensions and forwarding rules will also be removed.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button variant="destructive" onClick={handleDelete} disabled={deletePhoneNumber.isPending}>
            {deletePhoneNumber.isPending ? "Deleting..." : "Delete"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
