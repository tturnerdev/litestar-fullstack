import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

const DAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

const PRESETS = {
  weekdays: { days: [0, 1, 2, 3, 4], label: "Weekdays" },
  weekends: { days: [5, 6], label: "Weekends" },
  everyday: { days: [0, 1, 2, 3, 4, 5, 6], label: "Every Day" },
}

interface DndSchedulePickerProps {
  startTime: string
  endTime: string
  selectedDays: number[]
  onStartTimeChange: (value: string) => void
  onEndTimeChange: (value: string) => void
  onDaysChange: (days: number[]) => void
}

export function DndSchedulePicker({
  startTime,
  endTime,
  selectedDays,
  onStartTimeChange,
  onEndTimeChange,
  onDaysChange,
}: DndSchedulePickerProps) {
  function toggleDay(day: number) {
    const next = selectedDays.includes(day)
      ? selectedDays.filter((d) => d !== day)
      : [...selectedDays, day].sort()
    onDaysChange(next)
  }

  function applyPreset(preset: keyof typeof PRESETS) {
    onDaysChange(PRESETS[preset].days)
  }

  const durationText = getDurationText(startTime, endTime)

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label htmlFor="schedule-start">Start time</Label>
          <Input
            id="schedule-start"
            type="time"
            value={startTime}
            onChange={(e) => onStartTimeChange(e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="schedule-end">End time</Label>
          <Input
            id="schedule-end"
            type="time"
            value={endTime}
            onChange={(e) => onEndTimeChange(e.target.value)}
          />
        </div>
      </div>

      {durationText && (
        <p className="text-xs text-muted-foreground">{durationText}</p>
      )}

      <div className="space-y-3">
        <Label>Days of week</Label>
        <div className="flex flex-wrap gap-2">
          {DAY_LABELS.map((label, index) => (
            <Button
              key={label}
              size="sm"
              variant={selectedDays.includes(index) ? "default" : "outline"}
              onClick={() => toggleDay(index)}
              className="w-12"
            >
              {label}
            </Button>
          ))}
        </div>

        <div className="flex flex-wrap gap-2">
          {Object.entries(PRESETS).map(([key, preset]) => (
            <Button
              key={key}
              size="sm"
              variant="ghost"
              className="h-7 text-xs"
              onClick={() => applyPreset(key as keyof typeof PRESETS)}
            >
              {preset.label}
            </Button>
          ))}
        </div>
      </div>

      <ScheduleVisual startTime={startTime} endTime={endTime} selectedDays={selectedDays} />
    </div>
  )
}

function ScheduleVisual({ startTime, endTime, selectedDays }: { startTime: string; endTime: string; selectedDays: number[] }) {
  if (!startTime || !endTime || selectedDays.length === 0) return null

  const startMinutes = timeToMinutes(startTime)
  const endMinutes = timeToMinutes(endTime)
  const startPercent = (startMinutes / 1440) * 100
  const widthPercent = startMinutes < endMinutes
    ? ((endMinutes - startMinutes) / 1440) * 100
    : ((1440 - startMinutes + endMinutes) / 1440) * 100

  return (
    <div className="space-y-2">
      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Schedule preview</p>
      <div className="space-y-1">
        {DAY_LABELS.map((label, index) => (
          <div key={label} className="flex items-center gap-2">
            <span className={`w-8 text-xs ${selectedDays.includes(index) ? "font-medium" : "text-muted-foreground"}`}>
              {label}
            </span>
            <div className="relative h-4 flex-1 rounded bg-muted">
              {selectedDays.includes(index) && (
                <div
                  className="absolute inset-y-0 rounded bg-destructive/30"
                  style={{
                    left: `${startPercent}%`,
                    width: `${widthPercent}%`,
                  }}
                />
              )}
            </div>
          </div>
        ))}
        <div className="flex justify-between text-xs text-muted-foreground">
          <span>12am</span>
          <span>6am</span>
          <span>12pm</span>
          <span>6pm</span>
          <span>12am</span>
        </div>
      </div>
    </div>
  )
}

function timeToMinutes(time: string): number {
  const [hours, minutes] = time.split(":").map(Number)
  return (hours ?? 0) * 60 + (minutes ?? 0)
}

function getDurationText(start: string, end: string): string | null {
  if (!start || !end) return null
  const startMins = timeToMinutes(start)
  const endMins = timeToMinutes(end)
  const diff = startMins < endMins ? endMins - startMins : 1440 - startMins + endMins
  const hours = Math.floor(diff / 60)
  const mins = diff % 60
  if (hours === 0) return `DND active for ${mins} minutes`
  if (mins === 0) return `DND active for ${hours} hours`
  return `DND active for ${hours}h ${mins}m`
}
