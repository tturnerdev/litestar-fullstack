import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import type { Device } from "@/lib/api/hooks/devices"
import { useDeleteDevice } from "@/lib/api/hooks/devices"

interface DeviceDeleteDialogProps {
  device: Device
  open: boolean
  onOpenChange: (open: boolean) => void
  onDeleted?: () => void
}

export function DeviceDeleteDialog({ device, open, onOpenChange, onDeleted }: DeviceDeleteDialogProps) {
  const deleteDevice = useDeleteDevice()

  const handleDelete = async () => {
    await deleteDevice.mutateAsync(device.id)
    onOpenChange(false)
    onDeleted?.()
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Delete Device</DialogTitle>
          <DialogDescription>
            Are you sure you want to delete <span className="font-medium text-foreground">{device.name}</span>? This action cannot be undone. The device will be decommissioned and removed from
            the system.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={handleDelete} disabled={deleteDevice.isPending}>
            {deleteDevice.isPending ? "Deleting..." : "Delete Device"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
