import { useState } from "react"
import { AlertTriangle, Loader2, Power, RefreshCw, RotateCcw, Trash2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"

// ---------------------------------------------------------------------------
// Confirmation Dialog (reusable)
// ---------------------------------------------------------------------------

interface ConfirmDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description: string
  confirmLabel: string
  variant?: "default" | "destructive"
  isPending?: boolean
  onConfirm: () => void
}

function ConfirmDialog({ open, onOpenChange, title, description, confirmLabel, variant = "default", isPending, onConfirm }: ConfirmDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {variant === "destructive" && <AlertTriangle className="h-5 w-5 text-destructive" />}
            {title}
          </DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isPending}>
            Cancel
          </Button>
          <Button
            variant={variant === "destructive" ? "destructive" : "default"}
            onClick={() => {
              onConfirm()
              onOpenChange(false)
            }}
            disabled={isPending}
          >
            {isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Reboot Button
// ---------------------------------------------------------------------------

interface RebootButtonProps {
  onReboot: () => void
  isPending?: boolean
  size?: "default" | "sm" | "lg" | "icon"
}

export function RebootButton({ onReboot, isPending, size = "default" }: RebootButtonProps) {
  const [open, setOpen] = useState(false)

  return (
    <>
      <Button variant="outline" size={size} onClick={() => setOpen(true)} disabled={isPending}>
        {isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
        Reboot
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title="Reboot Device"
        description="This will send a reboot command to the device. Active calls will be disconnected. The device will be temporarily unavailable."
        confirmLabel="Reboot"
        isPending={isPending}
        onConfirm={onReboot}
      />
    </>
  )
}

// ---------------------------------------------------------------------------
// Reprovision Button
// ---------------------------------------------------------------------------

interface ReprovisionButtonProps {
  onReprovision: () => void
  isPending?: boolean
  size?: "default" | "sm" | "lg" | "icon"
}

export function ReprovisionButton({ onReprovision, isPending, size = "default" }: ReprovisionButtonProps) {
  const [open, setOpen] = useState(false)

  return (
    <>
      <Button variant="outline" size={size} onClick={() => setOpen(true)} disabled={isPending}>
        {isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RotateCcw className="mr-2 h-4 w-4" />}
        Reprovision
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title="Reprovision Device"
        description="This will regenerate the device configuration and push it to the device. The device may restart during this process."
        confirmLabel="Reprovision"
        isPending={isPending}
        onConfirm={onReprovision}
      />
    </>
  )
}

// ---------------------------------------------------------------------------
// Deactivate / Activate Button
// ---------------------------------------------------------------------------

interface ToggleActiveButtonProps {
  isActive: boolean
  onToggle: () => void
  isPending?: boolean
  size?: "default" | "sm" | "lg" | "icon"
}

export function ToggleActiveButton({ isActive, onToggle, isPending, size = "default" }: ToggleActiveButtonProps) {
  const [open, setOpen] = useState(false)

  if (!isActive) {
    return (
      <Button variant="outline" size={size} onClick={onToggle} disabled={isPending}>
        {isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Power className="mr-2 h-4 w-4" />}
        Activate
      </Button>
    )
  }

  return (
    <>
      <Button variant="outline" size={size} onClick={() => setOpen(true)} disabled={isPending}>
        {isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Power className="mr-2 h-4 w-4" />}
        Deactivate
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title="Deactivate Device"
        description="Deactivating this device will prevent it from registering with the SIP server. It will appear offline and cannot make or receive calls."
        confirmLabel="Deactivate"
        variant="destructive"
        isPending={isPending}
        onConfirm={onToggle}
      />
    </>
  )
}

// ---------------------------------------------------------------------------
// Delete Button
// ---------------------------------------------------------------------------

interface DeleteButtonProps {
  deviceName: string
  onDelete: () => void
  isPending?: boolean
  size?: "default" | "sm" | "lg" | "icon"
}

export function DeleteButton({ deviceName, onDelete, isPending, size = "default" }: DeleteButtonProps) {
  const [open, setOpen] = useState(false)

  return (
    <>
      <Button variant="destructive" size={size} onClick={() => setOpen(true)} disabled={isPending}>
        {isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Trash2 className="mr-2 h-4 w-4" />}
        Delete
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title="Delete Device"
        description={`Are you sure you want to delete "${deviceName}"? This action cannot be undone. All line assignments and configuration will be permanently removed.`}
        confirmLabel="Delete"
        variant="destructive"
        isPending={isPending}
        onConfirm={onDelete}
      />
    </>
  )
}

// ---------------------------------------------------------------------------
// Grouped Actions Bar
// ---------------------------------------------------------------------------

interface DeviceActionsProps {
  deviceName: string
  isActive: boolean
  onReboot: () => void
  onReprovision: () => void
  onToggleActive: () => void
  onDelete: () => void
  rebootPending?: boolean
  reprovisionPending?: boolean
  togglePending?: boolean
  deletePending?: boolean
}

export function DeviceActions({
  deviceName,
  isActive,
  onReboot,
  onReprovision,
  onToggleActive,
  onDelete,
  rebootPending,
  reprovisionPending,
  togglePending,
  deletePending,
}: DeviceActionsProps) {
  return (
    <div className="flex flex-wrap gap-2">
      <RebootButton onReboot={onReboot} isPending={rebootPending} />
      <ReprovisionButton onReprovision={onReprovision} isPending={reprovisionPending} />
      <ToggleActiveButton isActive={isActive} onToggle={onToggleActive} isPending={togglePending} />
      <DeleteButton deviceName={deviceName} onDelete={onDelete} isPending={deletePending} />
    </div>
  )
}
