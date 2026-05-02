import { Loader2, Phone } from "lucide-react"
import { useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { useCreateExtension } from "@/lib/api/hooks/voice"

const DISPLAY_NAME_MAX_LENGTH = 50

export function CreateExtensionDialog({ trigger }: { trigger: React.ReactNode }) {
  const [open, setOpen] = useState(false)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const [extensionNumber, setExtensionNumber] = useState("")
  const [extensionNumberError, setExtensionNumberError] = useState("")
  const [displayName, setDisplayName] = useState("")
  const [isActive, setIsActive] = useState(true)
  const createMutation = useCreateExtension()

  function resetForm() {
    setExtensionNumber("")
    setExtensionNumberError("")
    setDisplayName("")
    setIsActive(true)
  }

  function handleExtensionNumberChange(value: string) {
    setExtensionNumber(value)
    if (value && !/^\d+$/.test(value)) {
      setExtensionNumberError("Extension number must contain only digits")
    } else {
      setExtensionNumberError("")
    }
  }

  function handleDisplayNameChange(value: string) {
    if (value.length <= DISPLAY_NAME_MAX_LENGTH) {
      setDisplayName(value)
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!extensionNumber.trim() || extensionNumberError) return
    createMutation.mutate(
      {
        extensionNumber: extensionNumber.trim(),
        displayName: displayName.trim(),
        isActive,
      },
      {
        onSuccess: () => {
          resetForm()
          setOpen(false)
          setTimeout(() => triggerRef.current?.focus(), 0)
        },
      },
    )
  }

  const isFormValid = extensionNumber.trim() && !extensionNumberError

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        setOpen(v)
        if (!v) resetForm()
      }}
    >
      <DialogTrigger asChild ref={triggerRef}>
        {trigger}
      </DialogTrigger>
      <DialogContent>
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Phone className="h-5 w-5" />
              Add Extension
            </DialogTitle>
            <DialogDescription>Create a new internal extension for call routing.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="ext-number">
                Extension Number <span className="text-destructive">*</span>
              </Label>
              <Input
                id="ext-number"
                placeholder="1001"
                value={extensionNumber}
                onChange={(e) => handleExtensionNumberChange(e.target.value)}
                required
                aria-invalid={!!extensionNumberError}
              />
              {extensionNumberError ? (
                <p className="text-xs text-destructive">{extensionNumberError}</p>
              ) : (
                <p className="text-xs text-muted-foreground">Unique number used for internal call routing</p>
              )}
            </div>
            <div className="grid gap-2">
              <Label htmlFor="ext-name">Display Name</Label>
              <Input id="ext-name" placeholder="Front Desk" value={displayName} onChange={(e) => handleDisplayNameChange(e.target.value)} maxLength={DISPLAY_NAME_MAX_LENGTH} />
              <div className="flex items-center justify-between">
                <p className="text-xs text-muted-foreground">Name shown on caller ID and in the directory</p>
                <span className="text-xs text-muted-foreground">
                  {displayName.length}/{DISPLAY_NAME_MAX_LENGTH}
                </span>
              </div>
            </div>
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div className="space-y-0.5">
                <Label htmlFor="ext-active">Active</Label>
                <p className="text-xs text-muted-foreground">Extension will be available for call routing</p>
              </div>
              <Switch id="ext-active" checked={isActive} onCheckedChange={setIsActive} />
            </div>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!isFormValid || createMutation.isPending}>
              {createMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Creating...
                </>
              ) : (
                "Create"
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
