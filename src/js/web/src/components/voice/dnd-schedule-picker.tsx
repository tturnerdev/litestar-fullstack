import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { CalendarClock, Check, X } from "lucide-react"

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

  function clearSchedule() {
    onStartTimeChange("")
    onEndTimeChange("")
    onDaysChange([])
  }

  function isPresetActive(preset: keyof typeof PRESETS): boolean {
    const presetDays = PRESETS[preset].days
    if (selectedDays.length !== presetDays.length) return false
    return presetDays.every((d) => selectedDays.includes(d))
  }

  const durationText = getDurationText(startTime, endTime)
  const weeklyHoursText = getWeeklyHoursText(startTime, endTime, selectedDays.length)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <CalendarClock className="h-5 w-5 text-muted-foreground" />
          <h3 className="text-sm font-semibold">Schedule</h3>
        </div>
        {(startTime || endTime || selectedDays.length > 0) && (
          <Button variant="ghost" size="sm" className="h-7 text-xs text-muted-foreground" onClick={clearSchedule}>
            <X className="mr-1 h-3 w-3" />
            Clear schedule
          </Button>
        )}
      </div>

      <Separator />

      {/* Time inputs */}
      <div className="space-y-3">
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
      </div>

      <Separator />

      {/* Day picker */}
      <div className="space-y-3">
        <Label>Days of week</Label>
        <div className="flex flex-wrap gap-2">
          {DAY_LABELS.map((label, index) => (
            <button
              key={label}
              type="button"
              onClick={() => toggleDay(index)}
              className={`inline-flex h-9 items-center justify-center rounded-full px-4 text-sm font-medium transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 ${
                selectedDays.includes(index)
                  ? "bg-primary text-primary-foreground shadow-sm"
                  : "border border-input bg-background text-muted-foreground hover:bg-accent hover:text-accent-foreground"
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {weeklyHoursText && (
          <p className="text-xs font-medium text-muted-foreground">{weeklyHoursText}</p>
        )}
      </div>

      <Separator />

      {/* Presets */}
      <div className="space-y-3">
        <Label>Quick presets</Label>
        <div className="flex flex-wrap gap-2">
          {Object.entries(PRESETS).map(([key, preset]) => {
            const active = isPresetActive(key as keyof typeof PRESETS)
            return (
              <button
                key={key}
                type="button"
                onClick={() => applyPreset(key as keyof typeof PRESETS)}
                className={`inline-flex h-8 items-center gap-1.5 rounded-full border px-3 text-xs font-medium transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 ${
                  active
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-input bg-background text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                }`}
              >
                {active && <Check className="h-3 w-3" />}
                {preset.label}
              </button>
            )
          })}
        </div>
      </div>

      <Separator />

      {/* Schedule visual */}
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

  const tooltipLabel = `${formatTime12h(startTime)} - ${formatTime12h(endTime)}`

  return (
    <div className="space-y-2">
      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Schedule preview</p>
      <div className="space-y-1">
        {DAY_LABELS.map((label, index) => {
          const isSelected = selectedDays.includes(index)
          return (
            <div key={label} className="flex items-center gap-2">
              <span className={`w-8 text-xs ${isSelected ? "font-medium" : "text-muted-foreground"}`}>
                {label}
              </span>
              <div className="relative h-4 flex-1 rounded bg-muted">
                {isSelected && (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <div
                        className="absolute inset-y-0 rounded bg-destructive/30 transition-all hover:bg-destructive/50"
                        style={{
                          left: `${startPercent}%`,
                          width: `${widthPercent}%`,
                        }}
                      />
                    </TooltipTrigger>
                    <TooltipContent>
                      <span>{label}: {tooltipLabel}</span>
                    </TooltipContent>
                  </Tooltip>
                )}
              </div>
            </div>
          )
        })}
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

function formatTime12h(time: string): string {
  const [hoursStr, minutesStr] = time.split(":")
  let hours = Number(hoursStr)
  const minutes = minutesStr ?? "00"
  const ampm = hours >= 12 ? "PM" : "AM"
  hours = hours % 12
  if (hours === 0) hours = 12
  return `${hours}:${minutes} ${ampm}`
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

function getWeeklyHoursText(start: string, end: string, dayCount: number): string | null {
  if (!start || !end || dayCount === 0) return null
  const startMins = timeToMinutes(start)
  const endMins = timeToMinutes(end)
  const diff = startMins < endMins ? endMins - startMins : 1440 - startMins + endMins
  const totalMinutes = diff * dayCount
  const totalHours = Math.floor(totalMinutes / 60)
  const remainingMins = totalMinutes % 60
  if (remainingMins === 0) return `${totalHours}h per week`
  return `${totalHours}h ${remainingMins}m per week`
}
