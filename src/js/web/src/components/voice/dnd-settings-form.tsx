import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useDndSettings, useToggleDnd, useUpdateDndSettings } from "@/lib/api/hooks/voice"

const DAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

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

  function toggleDay(day: number) {
    const days = scheduleDays ?? data?.scheduleDays ?? []
    const next = days.includes(day) ? days.filter((d) => d !== day) : [...days, day].sort()
    setScheduleDays(next)
    setDirty(true)
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Do Not Disturb</CardTitle>
        <Button variant={data.isEnabled ? "destructive" : "default"} size="sm" onClick={handleToggle} disabled={toggleMutation.isPending}>
          {data.isEnabled ? "Disable DND" : "Enable DND"}
        </Button>
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
        </div>

        {currentMode === "scheduled" && (
          <>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="dnd-start">Start time</Label>
                <Input
                  id="dnd-start"
                  type="time"
                  value={currentStart}
                  onChange={(e) => {
                    setScheduleStart(e.target.value)
                    setDirty(true)
                  }}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="dnd-end">End time</Label>
                <Input
                  id="dnd-end"
                  type="time"
                  value={currentEnd}
                  onChange={(e) => {
                    setScheduleEnd(e.target.value)
                    setDirty(true)
                  }}
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label>Days of week</Label>
              <div className="flex flex-wrap gap-2">
                {DAY_LABELS.map((label, index) => (
                  <Button key={label} size="sm" variant={currentDays.includes(index) ? "default" : "outline"} onClick={() => toggleDay(index)}>
                    {label}
                  </Button>
                ))}
              </div>
            </div>
          </>
        )}

        <div className="space-y-2">
          <Label htmlFor="dnd-allow">Allow list (comma-separated numbers)</Label>
          <Input
            id="dnd-allow"
            placeholder="+15551234567, +15559876543"
            value={currentAllowList}
            onChange={(e) => {
              setAllowList(e.target.value)
              setDirty(true)
            }}
          />
        </div>

        <Button onClick={handleSave} disabled={!dirty || updateMutation.isPending}>
          {updateMutation.isPending ? "Saving..." : "Save changes"}
        </Button>
      </CardContent>
    </Card>
  )
}
