import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useCreateExtension } from "@/lib/api/hooks/voice"

export function CreateExtensionDialog({ trigger }: { trigger: React.ReactNode }) {
  const [open, setOpen] = useState(false)
  const [extensionNumber, setExtensionNumber] = useState("")
  const [displayName, setDisplayName] = useState("")
  const createMutation = useCreateExtension()

  function resetForm() {
    setExtensionNumber("")
    setDisplayName("")
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!extensionNumber.trim()) return
    createMutation.mutate(
      {
        extensionNumber: extensionNumber.trim(),
        displayName: displayName.trim(),
      },
      {
        onSuccess: () => {
          resetForm()
          setOpen(false)
        },
      },
    )
  }

  return (
    <Dialog open={open} onOpenChange={(v) => { setOpen(v); if (!v) resetForm() }}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent>
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Add Extension</DialogTitle>
            <DialogDescription>Create a new internal extension for call routing.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="ext-number">Extension Number</Label>
              <Input
                id="ext-number"
                placeholder="1001"
                value={extensionNumber}
                onChange={(e) => setExtensionNumber(e.target.value)}
                required
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="ext-name">Display Name</Label>
              <Input
                id="ext-name"
                placeholder="Front Desk"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!extensionNumber.trim() || createMutation.isPending}>
              {createMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
