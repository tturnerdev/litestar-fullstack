import { Loader2, Phone } from "lucide-react"
import { useEffect, useMemo, useState } from "react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Switch } from "@/components/ui/switch"
import { type Extension, usePhoneNumbers, useUpdateExtension } from "@/lib/api/hooks/voice"
import { cn } from "@/lib/utils"

const DISPLAY_NAME_MAX = 100

/** Sentinel value used for the "None" phone-number option. */
const PHONE_NONE = "__none__"

interface EditExtensionDialogProps {
  extension: Extension
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function EditExtensionDialog({ extension, open, onOpenChange }: EditExtensionDialogProps) {
  const [displayName, setDisplayName] = useState(extension.displayName ?? "")
  const [isActive, setIsActive] = useState(extension.isActive)
  const [phoneNumberId, setPhoneNumberId] = useState(extension.phoneNumberId ?? PHONE_NONE)
  const updateExtension = useUpdateExtension(extension.id)
  const { data: phoneNumbers } = usePhoneNumbers(1, 100)

  // Reset form state when the dialog opens or the extension changes
  useEffect(() => {
    if (open) {
      setDisplayName(extension.displayName ?? "")
      setIsActive(extension.isActive)
      setPhoneNumberId(extension.phoneNumberId ?? PHONE_NONE)
    }
  }, [open, extension])

  const isDirty = useMemo(() => {
    if (displayName !== (extension.displayName ?? "")) return true
    if (isActive !== extension.isActive) return true
    const currentPhone = extension.phoneNumberId ?? PHONE_NONE
    if (phoneNumberId !== currentPhone) return true
    return false
  }, [displayName, isActive, phoneNumberId, extension])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    const payload: Record<string, unknown> = {}
    if (displayName !== (extension.displayName ?? "")) {
      payload.displayName = displayName || null
    }
    if (isActive !== extension.isActive) {
      payload.isActive = isActive
    }
    const resolvedPhone = phoneNumberId === PHONE_NONE ? null : phoneNumberId
    if (resolvedPhone !== (extension.phoneNumberId ?? null)) {
      payload.phoneNumberId = resolvedPhone
    }

    if (Object.keys(payload).length === 0) {
      onOpenChange(false)
      return
    }

    updateExtension.mutate(payload, {
      onSuccess: () => {
        onOpenChange(false)
      },
    })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Phone className="h-5 w-5 text-muted-foreground" />
              Edit Extension
            </DialogTitle>
            <DialogDescription>
              Update settings for extension <span className="font-mono font-medium">{extension.extensionNumber}</span>.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            {/* Extension Number (read-only context) */}
            <div className="flex items-center justify-between rounded-md bg-muted/50 px-3 py-2.5">
              <div className="space-y-0.5">
                <p className="text-xs text-muted-foreground">Extension Number</p>
                <p className="font-mono text-sm font-medium">{extension.extensionNumber}</p>
              </div>
            </div>

            <Separator />

            {/* Display Name */}
            <div className="space-y-2">
              <Label htmlFor="edit-ext-name">Display Name</Label>
              <Input
                id="edit-ext-name"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value.slice(0, DISPLAY_NAME_MAX))}
                placeholder="Front Desk"
                maxLength={DISPLAY_NAME_MAX}
              />
              <div className="flex items-center justify-between">
                <p className="text-xs text-muted-foreground">Name shown in the directory and call logs.</p>
                <p
                  className={cn(
                    "shrink-0 text-xs",
                    displayName.length >= DISPLAY_NAME_MAX ? "text-destructive" : displayName.length >= DISPLAY_NAME_MAX * 0.8 ? "text-amber-500" : "text-muted-foreground",
                  )}
                >
                  {displayName.length}/{DISPLAY_NAME_MAX}
                </p>
              </div>
            </div>

            {/* Phone Number */}
            <div className="space-y-2">
              <Label>Phone Number</Label>
              <Select value={phoneNumberId} onValueChange={setPhoneNumberId}>
                <SelectTrigger>
                  <SelectValue placeholder="None (optional)" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={PHONE_NONE}>None</SelectItem>
                  {phoneNumbers?.items.map((pn) => (
                    <SelectItem key={pn.id} value={pn.id}>
                      {pn.number}
                      {pn.label ? ` - ${pn.label}` : ""}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">Optionally link a DID number that routes directly to this extension.</p>
            </div>

            <Separator />

            {/* Active toggle */}
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label htmlFor="edit-ext-active">Active</Label>
                <p className="text-xs text-muted-foreground">Whether this extension can receive calls.</p>
              </div>
              <Switch id="edit-ext-active" checked={isActive} onCheckedChange={setIsActive} />
            </div>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!isDirty || updateExtension.isPending}>
              {updateExtension.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {updateExtension.isPending ? "Saving..." : "Save changes"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
