import { AlertCircle, BellOff, BellRing, Calendar, Clock, Moon, Sun, X } from "lucide-react"
import { type KeyboardEvent, useRef, useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { DndSchedulePicker } from "@/components/voice/dnd-schedule-picker"
import { useDndSettings, useToggleDnd, useUpdateDndSettings } from "@/lib/api/hooks/voice"
import { cn } from "@/lib/utils"

const MODE_OPTIONS = [
  {
    value: "off",
    label: "Off",
    description: "DND is disabled. All calls will ring normally.",
    indicator: "bg-emerald-500",
    icon: Sun,
  },
  {
    value: "always",
    label: "Always",
    description: "All incoming calls will be silenced at all times.",
    indicator: "bg-red-500",
    icon: Moon,
  },
  {
    value: "scheduled",
    label: "Scheduled",
    description: "Calls are silenced during the scheduled time windows.",
    indicator: "bg-amber-500",
    icon: Calendar,
  },
] as const

export function DndSettingsForm({ extensionId }: { extensionId: string }) {
  const { data, isLoading, isError, refetch } = useDndSettings(extensionId)
  const updateMutation = useUpdateDndSettings(extensionId)
  const toggleMutation = useToggleDnd(extensionId)
  const [dirty, setDirty] = useState(false)

  const [mode, setMode] = useState("")
  const [scheduleStart, setScheduleStart] = useState("")
  const [scheduleEnd, setScheduleEnd] = useState("")
  const [scheduleDays, setScheduleDays] = useState<number[] | null>(null)
  const [allowListNumbers, setAllowListNumbers] = useState<string[] | null>(null)
  const [allowInput, setAllowInput] = useState("")
  const allowInputRef = useRef<HTMLInputElement>(null)

  if (isLoading) return <SkeletonCard />

  if (isError || !data) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load DND settings"
        description="Something went wrong. Please try again."
        action={
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            Try again
          </Button>
        }
      />
    )
  }

  const currentMode = mode || data.mode
  const currentStart = scheduleStart || data.scheduleStart || ""
  const currentEnd = scheduleEnd || data.scheduleEnd || ""
  const currentDays = scheduleDays ?? data.scheduleDays ?? []
  const currentAllowList = allowListNumbers ?? data.allowList ?? []

  function handleToggle() {
    toggleMutation.mutate()
  }

  function handleAddNumber() {
    const trimmed = allowInput.trim()
    if (!trimmed) return
    if (!currentAllowList.includes(trimmed)) {
      const updated = [...currentAllowList, trimmed]
      setAllowListNumbers(updated)
      setDirty(true)
    }
    setAllowInput("")
    allowInputRef.current?.focus()
  }

  function handleRemoveNumber(number: string) {
    const updated = currentAllowList.filter((n) => n !== number)
    setAllowListNumbers(updated)
    setDirty(true)
  }

  function handleAllowInputKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") {
      e.preventDefault()
      handleAddNumber()
    } else if (e.key === "Backspace" && !allowInput && currentAllowList.length > 0) {
      handleRemoveNumber(currentAllowList[currentAllowList.length - 1])
    }
  }

  function handleSave() {
    const payload: Record<string, unknown> = {}
    if (mode) payload.mode = mode
    if (scheduleStart) payload.scheduleStart = scheduleStart
    if (scheduleEnd) payload.scheduleEnd = scheduleEnd
    if (scheduleDays !== null) payload.scheduleDays = scheduleDays
    if (allowListNumbers !== null) {
      payload.allowList = allowListNumbers
    }

    updateMutation.mutate(payload, {
      onSuccess: () => setDirty(false),
    })
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Do Not Disturb</CardTitle>
        <CardDescription>Configure when incoming calls should be silenced.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Status banner */}
        <div
          className={cn(
            "flex items-center justify-between rounded-lg border p-4",
            data.isEnabled ? "border-destructive/30 bg-destructive/10" : "border-emerald-500/30 bg-emerald-500/10",
          )}
        >
          <div className="flex items-center gap-3">
            {data.isEnabled ? (
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-destructive/20">
                <BellOff className="h-5 w-5 text-destructive" />
              </div>
            ) : (
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-emerald-500/20">
                <BellRing className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
              </div>
            )}
            <div>
              <p className={cn("text-sm font-semibold", data.isEnabled ? "text-destructive" : "text-emerald-700 dark:text-emerald-400")}>
                {data.isEnabled ? "Do Not Disturb is ON" : "Do Not Disturb is OFF"}
              </p>
              <p className="text-xs text-muted-foreground">{data.isEnabled ? "Incoming calls are being silenced" : "All calls will ring normally"}</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Label htmlFor="dnd-toggle" className="text-sm text-muted-foreground">
              {data.isEnabled ? "Enabled" : "Disabled"}
            </Label>
            <Switch id="dnd-toggle" checked={data.isEnabled} onCheckedChange={handleToggle} disabled={toggleMutation.isPending} />
          </div>
        </div>

        <Separator />

        {/* Mode cards */}
        <div className="space-y-3">
          <Label>Mode</Label>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {MODE_OPTIONS.map((opt) => {
              const isSelected = currentMode === opt.value
              const IconComponent = opt.icon
              return (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => {
                    setMode(opt.value)
                    setDirty(true)
                  }}
                  className={cn(
                    "relative flex flex-col items-start gap-2 rounded-lg border-2 p-4 text-left transition-all hover:bg-accent/50",
                    isSelected ? "border-primary bg-accent/30 shadow-sm" : "border-border",
                  )}
                >
                  <div className="flex w-full items-center gap-2">
                    <span className={cn("inline-block h-2.5 w-2.5 rounded-full", opt.indicator)} />
                    <IconComponent className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm font-medium">{opt.label}</span>
                    {isSelected && (
                      <Badge variant="secondary" className="ml-auto text-xs">
                        Selected
                      </Badge>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed">{opt.description}</p>
                </button>
              )
            })}
          </div>
        </div>

        {currentMode === "scheduled" && (
          <>
            <Separator />
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-muted-foreground" />
                <Label>Schedule</Label>
              </div>
              <div className="rounded-lg border border-border/60 bg-muted/20 p-4">
                <DndSchedulePicker
                  startTime={currentStart}
                  endTime={currentEnd}
                  selectedDays={currentDays}
                  onStartTimeChange={(v) => {
                    setScheduleStart(v)
                    setDirty(true)
                  }}
                  onEndTimeChange={(v) => {
                    setScheduleEnd(v)
                    setDirty(true)
                  }}
                  onDaysChange={(days) => {
                    setScheduleDays(days)
                    setDirty(true)
                  }}
                />
              </div>
            </div>
          </>
        )}

        <Separator />

        {/* Allow list */}
        <div className="space-y-3">
          <Label>Allow list</Label>
          <p className="text-xs text-muted-foreground">Phone numbers that can bypass Do Not Disturb. Press Enter to add.</p>
          <div className="flex flex-wrap items-center gap-1.5 rounded-md border border-input bg-background px-3 py-2 focus-within:ring-2 focus-within:ring-ring focus-within:ring-offset-2 focus-within:ring-offset-background">
            {currentAllowList.map((num) => (
              <Badge key={num} variant="secondary" className="gap-1 font-mono text-xs">
                {num}
                <button type="button" onClick={() => handleRemoveNumber(num)} className="ml-0.5 rounded-sm hover:bg-muted-foreground/20" aria-label={`Remove ${num}`}>
                  <X className="h-3 w-3" />
                </button>
              </Badge>
            ))}
            <Input
              ref={allowInputRef}
              value={allowInput}
              onChange={(e) => setAllowInput(e.target.value)}
              onKeyDown={handleAllowInputKeyDown}
              placeholder={currentAllowList.length === 0 ? "+15551234567" : "Add number..."}
              className="h-7 min-w-[120px] flex-1 border-0 p-0 shadow-none focus-visible:ring-0"
            />
          </div>
          {allowInput.trim() && (
            <Button type="button" variant="outline" size="sm" onClick={handleAddNumber}>
              Add "{allowInput.trim()}"
            </Button>
          )}
        </div>

        <Separator />

        <Button onClick={handleSave} disabled={!dirty || updateMutation.isPending}>
          {updateMutation.isPending ? "Saving..." : "Save changes"}
        </Button>
      </CardContent>
    </Card>
  )
}
