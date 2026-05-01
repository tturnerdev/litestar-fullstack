import { useCallback, useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { type PhoneNumber, useUpdatePhoneNumber } from "@/lib/api/hooks/voice"

interface PhoneNumberEditSheetProps {
  phoneNumber: PhoneNumber
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function PhoneNumberEditSheet({ phoneNumber, open, onOpenChange }: PhoneNumberEditSheetProps) {
  const updatePhoneNumber = useUpdatePhoneNumber(phoneNumber.id)

  const [label, setLabel] = useState(phoneNumber.label ?? "")
  const [callerIdName, setCallerIdName] = useState(phoneNumber.callerIdName ?? "")
  const [isActive, setIsActive] = useState(phoneNumber.isActive)

  // Reset form state when the sheet opens or the phone number changes
  useEffect(() => {
    if (open) {
      setLabel(phoneNumber.label ?? "")
      setCallerIdName(phoneNumber.callerIdName ?? "")
      setIsActive(phoneNumber.isActive)
    }
  }, [open, phoneNumber.label, phoneNumber.callerIdName, phoneNumber.isActive])

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault()
      const payload: Record<string, unknown> = {
        label: label.trim() || null,
        callerIdName: callerIdName.trim() || null,
        isActive,
      }
      updatePhoneNumber.mutate(payload, {
        onSuccess: () => onOpenChange(false),
      })
    },
    [label, callerIdName, isActive, updatePhoneNumber, onOpenChange],
  )

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent>
        <SheetHeader>
          <SheetTitle>Edit Phone Number</SheetTitle>
          <SheetDescription>Update the label, caller ID name, or active status for {phoneNumber.number}.</SheetDescription>
        </SheetHeader>
        <form onSubmit={handleSubmit} className="flex flex-1 flex-col gap-6 overflow-y-auto px-4">
          <div className="space-y-2">
            <Label htmlFor="edit-label">Label</Label>
            <Input id="edit-label" placeholder="e.g. Main Line, Sales" value={label} onChange={(e) => setLabel(e.target.value)} />
            <p className="text-xs text-muted-foreground">A friendly name to identify this number.</p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="edit-caller-id">Caller ID Name</Label>
            <Input id="edit-caller-id" placeholder="e.g. Acme Corp" value={callerIdName} onChange={(e) => setCallerIdName(e.target.value)} maxLength={50} />
            <p className="text-xs text-muted-foreground">The name displayed for outbound calls (max 50 characters).</p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="edit-active">Status</Label>
            <Select value={isActive ? "active" : "inactive"} onValueChange={(v) => setIsActive(v === "active")}>
              <SelectTrigger id="edit-active">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="inactive">Inactive</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">Whether this number can receive and make calls.</p>
          </div>
          <SheetFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={updatePhoneNumber.isPending}>
              {updatePhoneNumber.isPending ? "Saving..." : "Save changes"}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  )
}
