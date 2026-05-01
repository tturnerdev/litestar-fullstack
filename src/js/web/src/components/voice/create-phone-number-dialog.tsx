import { useState } from "react"
import { Hash, Loader2, MapPin, Globe, Flag } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useCreatePhoneNumber } from "@/lib/api/hooks/voice"

const TYPE_OPTIONS = [
  { value: "local", label: "Local", icon: MapPin },
  { value: "toll_free", label: "Toll-Free", icon: Globe },
  { value: "international", label: "International", icon: Flag },
] as const

function getTypeLabel(value: string): string {
  return TYPE_OPTIONS.find((o) => o.value === value)?.label ?? value
}

export function CreatePhoneNumberDialog({ trigger }: { trigger: React.ReactNode }) {
  const [open, setOpen] = useState(false)
  const [number, setNumber] = useState("")
  const [numberError, setNumberError] = useState("")
  const [label, setLabel] = useState("")
  const [numberType, setNumberType] = useState("local")
  const [callerIdName, setCallerIdName] = useState("")
  const createMutation = useCreatePhoneNumber()

  function resetForm() {
    setNumber("")
    setNumberError("")
    setLabel("")
    setNumberType("local")
    setCallerIdName("")
  }

  function handleNumberChange(value: string) {
    setNumber(value)
    if (value && !/^\+\d+$/.test(value)) {
      setNumberError("Must be E.164 format: + followed by digits (e.g., +15551234567)")
    } else {
      setNumberError("")
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!number.trim() || numberError) return
    createMutation.mutate(
      {
        number: number.trim(),
        label: label.trim() || null,
        numberType,
        callerIdName: callerIdName.trim() || null,
      },
      {
        onSuccess: () => {
          toast.success("Phone number created successfully")
          resetForm()
          setOpen(false)
        },
      },
    )
  }

  const isFormValid = number.trim() && !numberError

  return (
    <Dialog open={open} onOpenChange={(v) => { setOpen(v); if (!v) resetForm() }}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent>
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Hash className="h-5 w-5" />
              Add Phone Number
            </DialogTitle>
            <DialogDescription>Assign a new DID phone number.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="pn-number">
                Phone Number <span className="text-destructive">*</span>
              </Label>
              <Input
                id="pn-number"
                placeholder="+15551234567"
                value={number}
                onChange={(e) => handleNumberChange(e.target.value)}
                required
                aria-invalid={!!numberError}
              />
              {numberError ? (
                <p className="text-xs text-destructive">{numberError}</p>
              ) : (
                <p className="text-xs text-muted-foreground">Enter in E.164 format, e.g., +15551234567</p>
              )}
            </div>
            <div className="grid gap-2">
              <Label htmlFor="pn-label">Label</Label>
              <Input
                id="pn-label"
                placeholder="Main Line"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">Optional friendly name for this number</p>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="pn-type">Type</Label>
              <Select value={numberType} onValueChange={setNumberType}>
                <SelectTrigger id="pn-type">
                  <SelectValue placeholder="Select a type..." />
                </SelectTrigger>
                <SelectContent>
                  {TYPE_OPTIONS.map(({ value, label: optLabel, icon: Icon }) => (
                    <SelectItem key={value} value={value}>
                      <span className="flex items-center gap-2">
                        <Icon className="h-4 w-4 text-muted-foreground" />
                        {optLabel}
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">Determines routing and billing for this number</p>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="pn-caller-id">Caller ID Name</Label>
              <Input
                id="pn-caller-id"
                placeholder="Acme Corp"
                value={callerIdName}
                onChange={(e) => setCallerIdName(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">Name displayed to the recipient on outgoing calls</p>
            </div>
            {(number.trim() || callerIdName.trim()) && (
              <div className="rounded-lg border bg-muted/50 p-3">
                <p className="mb-1 text-xs font-medium text-muted-foreground">Preview</p>
                <p className="text-sm">
                  {number.trim() && (
                    <span>Number: {number.trim()}</span>
                  )}
                  {number.trim() && <span className="text-muted-foreground"> &bull; </span>}
                  <span>Type: {getTypeLabel(numberType)}</span>
                  {callerIdName.trim() && (
                    <>
                      <span className="text-muted-foreground"> &bull; </span>
                      <span>Caller ID: {callerIdName.trim()}</span>
                    </>
                  )}
                </p>
              </div>
            )}
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
