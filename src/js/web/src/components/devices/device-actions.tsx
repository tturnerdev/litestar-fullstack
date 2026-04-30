import { useState } from "react"
import { AlertTriangle, Loader2, Power, RefreshCw, RotateCcw, Trash2 } from "lucide-react"
import { Button, buttonVariants } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
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
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Separator } from "@/components/ui/separator"
import { formatRelativeTimeShort } from "@/lib/date-utils"
import { cn } from "@/lib/utils"

// ---------------------------------------------------------------------------
// Confirmation Dialog (reusable) — non-destructive actions
// ---------------------------------------------------------------------------

interface ConfirmDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description: string
  confirmLabel: string
  isPending?: boolean
  onConfirm: () => void
}

function ConfirmDialog({ open, onOpenChange, title, description, confirmLabel, isPending, onConfirm }: ConfirmDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isPending}>
            Cancel
          </Button>
          <Button
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
// Destructive Confirmation Dialog — uses AlertDialog (no outside dismiss)
// ---------------------------------------------------------------------------

interface DestructiveDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description: string
  confirmLabel: string
  isPending?: boolean
  onConfirm: () => void
}

function DestructiveDialog({ open, onOpenChange, title, description, confirmLabel, isPending, onConfirm }: DestructiveDialogProps) {
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            {title}
          </AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={() => onOpenChange(false)} disabled={isPending}>
            Cancel
          </AlertDialogCancel>
          <AlertDialogAction
            className={buttonVariants({ variant: "destructive" })}
            onClick={() => {
              onConfirm()
              onOpenChange(false)
            }}
            disabled={isPending}
          >
            {isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {confirmLabel}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Reboot Button
// ---------------------------------------------------------------------------

interface RebootButtonProps {
  onReboot: () => void
  isPending?: boolean
  lastRebootedAt?: string
  size?: "default" | "sm" | "lg" | "icon"
}

export function RebootButton({ onReboot, isPending, lastRebootedAt, size = "default" }: RebootButtonProps) {
  const [open, setOpen] = useState(false)

  return (
    <>
      <Tooltip>
        <TooltipTrigger asChild>
          <div className="inline-flex flex-col items-start">
            <Button variant="outline" size={size} onClick={() => setOpen(true)} disabled={isPending}>
              {isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
              Reboot
            </Button>
            {lastRebootedAt && (
              <span className="mt-1 text-xs text-muted-foreground">
                Last rebooted: {formatRelativeTimeShort(lastRebootedAt)}
              </span>
            )}
          </div>
        </TooltipTrigger>
        <TooltipContent>Send a reboot command to the device</TooltipContent>
      </Tooltip>
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
      <Tooltip>
        <TooltipTrigger asChild>
          <Button variant="outline" size={size} onClick={() => setOpen(true)} disabled={isPending}>
            {isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RotateCcw className="mr-2 h-4 w-4" />}
            Reprovision
          </Button>
        </TooltipTrigger>
        <TooltipContent>Regenerate and push device configuration</TooltipContent>
      </Tooltip>
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
      <Tooltip>
        <TooltipTrigger asChild>
          <Button variant="outline" size={size} onClick={onToggle} disabled={isPending}>
            {isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Power className="mr-2 h-4 w-4" />}
            Activate
          </Button>
        </TooltipTrigger>
        <TooltipContent>Enable device registration with SIP server</TooltipContent>
      </Tooltip>
    )
  }

  return (
    <>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button variant="outline" size={size} onClick={() => setOpen(true)} disabled={isPending}>
            {isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Power className="mr-2 h-4 w-4" />}
            Deactivate
          </Button>
        </TooltipTrigger>
        <TooltipContent>Disable device registration with SIP server</TooltipContent>
      </Tooltip>
      <DestructiveDialog
        open={open}
        onOpenChange={setOpen}
        title="Deactivate Device"
        description="Deactivating this device will prevent it from registering with the SIP server. It will appear offline and cannot make or receive calls."
        confirmLabel="Deactivate"
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
      <Tooltip>
        <TooltipTrigger asChild>
          <Button variant="destructive" size={size} onClick={() => setOpen(true)} disabled={isPending}>
            {isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Trash2 className="mr-2 h-4 w-4" />}
            Delete
          </Button>
        </TooltipTrigger>
        <TooltipContent>Permanently remove this device</TooltipContent>
      </Tooltip>
      <DestructiveDialog
        open={open}
        onOpenChange={setOpen}
        title="Delete Device"
        description={`Are you sure you want to delete "${deviceName}"? This action cannot be undone. All line assignments and configuration will be permanently removed.`}
        confirmLabel="Delete"
        isPending={isPending}
        onConfirm={onDelete}
      />
    </>
  )
}

// ---------------------------------------------------------------------------
// Action Card (used in the grouped grid)
// ---------------------------------------------------------------------------

interface ActionCardProps {
  icon: React.ReactNode
  iconBgClass: string
  label: string
  subtitle: string
  tooltip: string
  disabled?: boolean
  onClick: () => void
}

function ActionCard({ icon, iconBgClass, label, subtitle, tooltip, disabled, onClick }: ActionCardProps) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          disabled={disabled}
          onClick={onClick}
          className={cn(
            "flex items-center gap-3 rounded-lg border bg-card p-3 text-left transition-colors",
            "hover:bg-accent/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
            disabled && "pointer-events-none opacity-50",
          )}
        >
          <div className={cn("flex h-9 w-9 shrink-0 items-center justify-center rounded-md", iconBgClass)}>
            {icon}
          </div>
          <div className="min-w-0">
            <p className="text-sm font-medium leading-none">{label}</p>
            <p className="mt-1 text-xs text-muted-foreground">{subtitle}</p>
          </div>
        </button>
      </TooltipTrigger>
      <TooltipContent>{tooltip}</TooltipContent>
    </Tooltip>
  )
}

// ---------------------------------------------------------------------------
// Grouped Actions Bar (2x2 card grid)
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
  lastRebootedAt?: string
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
  lastRebootedAt,
}: DeviceActionsProps) {
  const [rebootOpen, setRebootOpen] = useState(false)
  const [reprovisionOpen, setReprovisionOpen] = useState(false)
  const [toggleOpen, setToggleOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)

  const rebootSubtitle = lastRebootedAt
    ? `Restart device · Last: ${formatRelativeTimeShort(lastRebootedAt)}`
    : "Restart device"

  return (
    <>
      <div className="space-y-4">
        {/* Operational actions */}
        <div>
          <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">Operations</p>
          <div className="grid grid-cols-2 gap-3">
            <ActionCard
              icon={rebootPending ? <Loader2 className="h-4 w-4 animate-spin text-blue-700 dark:text-blue-300" /> : <RefreshCw className="h-4 w-4 text-blue-700 dark:text-blue-300" />}
              iconBgClass="bg-blue-100 dark:bg-blue-950"
              label="Reboot"
              subtitle={rebootSubtitle}
              tooltip="Send a reboot command to the device"
              disabled={rebootPending}
              onClick={() => setRebootOpen(true)}
            />
            <ActionCard
              icon={reprovisionPending ? <Loader2 className="h-4 w-4 animate-spin text-amber-700 dark:text-amber-300" /> : <RotateCcw className="h-4 w-4 text-amber-700 dark:text-amber-300" />}
              iconBgClass="bg-amber-100 dark:bg-amber-950"
              label="Reprovision"
              subtitle="Push config"
              tooltip="Regenerate and push device configuration"
              disabled={reprovisionPending}
              onClick={() => setReprovisionOpen(true)}
            />
          </div>
        </div>

        <Separator />

        {/* Management actions */}
        <div>
          <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">Management</p>
          <div className="grid grid-cols-2 gap-3">
            <ActionCard
              icon={togglePending ? <Loader2 className={cn("h-4 w-4 animate-spin", isActive ? "text-red-700 dark:text-red-300" : "text-green-700 dark:text-green-300")} /> : <Power className={cn("h-4 w-4", isActive ? "text-red-700 dark:text-red-300" : "text-green-700 dark:text-green-300")} />}
              iconBgClass={isActive ? "bg-red-100 dark:bg-red-950" : "bg-green-100 dark:bg-green-950"}
              label={isActive ? "Deactivate" : "Activate"}
              subtitle={isActive ? "Disable device" : "Enable device"}
              tooltip={isActive ? "Disable device registration with SIP server" : "Enable device registration with SIP server"}
              disabled={togglePending}
              onClick={() => {
                if (isActive) {
                  setToggleOpen(true)
                } else {
                  onToggleActive()
                }
              }}
            />
            <ActionCard
              icon={deletePending ? <Loader2 className="h-4 w-4 animate-spin text-red-700 dark:text-red-300" /> : <Trash2 className="h-4 w-4 text-red-700 dark:text-red-300" />}
              iconBgClass="bg-red-100 dark:bg-red-950"
              label="Delete"
              subtitle="Remove permanently"
              tooltip="Permanently remove this device and all configuration"
              disabled={deletePending}
              onClick={() => setDeleteOpen(true)}
            />
          </div>
        </div>
      </div>

      {/* Non-destructive confirmation dialogs */}
      <ConfirmDialog
        open={rebootOpen}
        onOpenChange={setRebootOpen}
        title="Reboot Device"
        description="This will send a reboot command to the device. Active calls will be disconnected. The device will be temporarily unavailable."
        confirmLabel="Reboot"
        isPending={rebootPending}
        onConfirm={onReboot}
      />
      <ConfirmDialog
        open={reprovisionOpen}
        onOpenChange={setReprovisionOpen}
        title="Reprovision Device"
        description="This will regenerate the device configuration and push it to the device. The device may restart during this process."
        confirmLabel="Reprovision"
        isPending={reprovisionPending}
        onConfirm={onReprovision}
      />

      {/* Destructive confirmation dialogs (AlertDialog - no outside dismiss) */}
      <DestructiveDialog
        open={toggleOpen}
        onOpenChange={setToggleOpen}
        title="Deactivate Device"
        description="Deactivating this device will prevent it from registering with the SIP server. It will appear offline and cannot make or receive calls."
        confirmLabel="Deactivate"
        isPending={togglePending}
        onConfirm={onToggleActive}
      />
      <DestructiveDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title="Delete Device"
        description={`Are you sure you want to delete "${deviceName}"? This action cannot be undone. All line assignments and configuration will be permanently removed.`}
        confirmLabel="Delete"
        isPending={deletePending}
        onConfirm={onDelete}
      />
    </>
  )
}
