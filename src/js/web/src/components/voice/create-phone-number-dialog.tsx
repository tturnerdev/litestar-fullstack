import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useCreatePhoneNumber } from "@/lib/api/hooks/voice"

export function CreatePhoneNumberDialog({ trigger }: { trigger: React.ReactNode }) {
  const [open, setOpen] = useState(false)
  const [number, setNumber] = useState("")
  const [label, setLabel] = useState("")
  const [numberType, setNumberType] = useState("local")
  const [callerIdName, setCallerIdName] = useState("")
  const createMutation = useCreatePhoneNumber()

  function resetForm() {
    setNumber("")
    setLabel("")
    setNumberType("local")
    setCallerIdName("")
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!number.trim()) return
    createMutation.mutate(
      {
        number: number.trim(),
        label: label.trim() || null,
        numberType,
        callerIdName: callerIdName.trim() || null,
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
            <DialogTitle>Add Phone Number</DialogTitle>
            <DialogDescription>Assign a new DID phone number.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="pn-number">Phone Number</Label>
              <Input
                id="pn-number"
                placeholder="+15551234567"
                value={number}
                onChange={(e) => setNumber(e.target.value)}
                required
              />
              <p className="text-xs text-muted-foreground">E.164 format (e.g. +15551234567)</p>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="pn-label">Label</Label>
              <Input
                id="pn-label"
                placeholder="Main Line"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="pn-type">Type</Label>
              <Select value={numberType} onValueChange={setNumberType}>
                <SelectTrigger id="pn-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="local">Local</SelectItem>
                  <SelectItem value="toll_free">Toll-Free</SelectItem>
                  <SelectItem value="international">International</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="pn-caller-id">Caller ID Name</Label>
              <Input
                id="pn-caller-id"
                placeholder="Acme Corp"
                value={callerIdName}
                onChange={(e) => setCallerIdName(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!number.trim() || createMutation.isPending}>
              {createMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
