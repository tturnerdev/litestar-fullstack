import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonCard } from "@/components/ui/skeleton"
import { DndSchedulePicker } from "@/components/voice/dnd-schedule-picker"
import { useDndSettings, useToggleDnd, useUpdateDndSettings } from "@/lib/api/hooks/voice"

const MODE_DESCRIPTIONS: Record<string, string> = {
  off: "DND is disabled. All calls will ring normally.",
  always: "All incoming calls will be silenced at all times.",
  scheduled: "Calls are silenced during the scheduled time windows.",
}

export function DndSettingsForm({ extensionId }: { extensionId: string }) {
  const { data, isLoading, isError } = useDndSettings(extensionId)
  const updateMutation = useUpdateDndSettings(extensionId)
  const toggleMutation = useToggleDnd(extensionId)
  const [dirty, setDirty] = useState(false)

  const [mode, setMode] = useState("")
  const [scheduleStart, setScheduleStart] = useState("")
  const [scheduleEnd, setScheduleEnd] = useState("")
  const [scheduleDays, setScheduleDays] = useState<number[] | null>(null)
  const [allowList, setAllowList] = useState("")

  if (isLoading) return <SkeletonCard />

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Do Not Disturb</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">Unable to load DND settings.</CardContent>
      </Card>
    )
  }

  const currentMode = mode || data.mode
  const currentStart = scheduleStart || data.scheduleStart || ""
  const currentEnd = scheduleEnd || data.scheduleEnd || ""
  const currentDays = scheduleDays ?? data.scheduleDays ?? []
  const currentAllowList = allowList || (data.allowList ?? []).join(", ")

  function handleToggle() {
    toggleMutation.mutate()
  }

  function handleSave() {
    const payload: Record<string, unknown> = {}
    if (mode) payload.mode = mode
    if (scheduleStart) payload.scheduleStart = scheduleStart
    if (scheduleEnd) payload.scheduleEnd = scheduleEnd
    if (scheduleDays !== null) payload.scheduleDays = scheduleDays
    if (allowList) {
      payload.allowList = allowList
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    }

    updateMutation.mutate(payload, {
      onSuccess: () => setDirty(false),
    })
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle>Do Not Disturb</CardTitle>
          <CardDescription>
            {data.isEnabled ? "DND is currently active." : "DND is currently inactive."}
          </CardDescription>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={data.isEnabled ? "destructive" : "secondary"}>
            {data.isEnabled ? "Active" : "Inactive"}
          </Badge>
          <Button
            variant={data.isEnabled ? "destructive" : "default"}
            size="sm"
            onClick={handleToggle}
            disabled={toggleMutation.isPending}
          >
            {data.isEnabled ? "Disable DND" : "Enable DND"}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <Label>Mode</Label>
          <Select
            value={currentMode}
            onValueChange={(v) => {
              setMode(v)
              setDirty(true)
            }}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="off">Off</SelectItem>
              <SelectItem value="always">Always</SelectItem>
              <SelectItem value="scheduled">Scheduled</SelectItem>
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">{MODE_DESCRIPTIONS[currentMode]}</p>
        </div>

        {currentMode === "scheduled" && (
          <div className="space-y-2">
            <Label>Schedule</Label>
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
        )}

        <div className="space-y-2">
          <Label htmlFor="dnd-allow">Allow list</Label>
          <p className="text-xs text-muted-foreground">
            Comma-separated phone numbers that can bypass DND.
          </p>
          <Input
            id="dnd-allow"
            placeholder="+15551234567, +15559876543"
            value={currentAllowList}
            onChange={(e) => {
              setAllowList(e.target.value)
              setDirty(true)
            }}
          />
          {currentAllowList && (
            <div className="flex flex-wrap gap-1">
              {currentAllowList
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean)
                .map((num) => (
                  <Badge key={num} variant="secondary" className="text-xs font-mono">
                    {num}
                  </Badge>
                ))}
            </div>
          )}
        </div>

        <Button onClick={handleSave} disabled={!dirty || updateMutation.isPending}>
          {updateMutation.isPending ? "Saving..." : "Save changes"}
        </Button>
      </CardContent>
    </Card>
  )
}
