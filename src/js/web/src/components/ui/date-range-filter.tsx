import { Calendar } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"

// ── Date preset definitions ──────────────────────────────────────────────

export const DATE_PRESETS = [
  { label: "Today", days: 0 },
  { label: "Last 7 days", days: 7 },
  { label: "Last 30 days", days: 30 },
  { label: "Last 90 days", days: 90 },
  { label: "All time", days: -1 },
] as const

// ── Helpers ──────────────────────────────────────────────────────────────

export function formatDateForInput(date: Date): string {
  return date.toISOString().split("T")[0]
}

export function getPresetDates(days: number): { start: string; end: string } {
  const now = new Date()
  const end = formatDateForInput(now)
  if (days < 0) return { start: "", end: "" }
  if (days === 0) return { start: end, end }
  const start = new Date(now)
  start.setDate(start.getDate() - days)
  return { start: formatDateForInput(start), end }
}

export function getPresetLabel(startDate: string, endDate: string): string | null {
  if (!startDate && !endDate) return null
  const now = new Date()
  const todayStr = formatDateForInput(now)
  if (startDate === todayStr && endDate === todayStr) return "Today"
  for (const preset of DATE_PRESETS) {
    if (preset.days <= 0) continue
    const { start, end } = getPresetDates(preset.days)
    if (startDate === start && endDate === end) return preset.label
  }
  return "Custom"
}

/**
 * Check whether a date string falls within a start/end range (inclusive).
 * If both start and end are empty, all dates pass.
 */
export function isDateInRange(
  dateStr: string | null | undefined,
  startDate: string,
  endDate: string,
): boolean {
  if (!startDate && !endDate) return true
  if (!dateStr) return false
  const d = new Date(dateStr)
  if (Number.isNaN(d.getTime())) return false
  if (startDate) {
    const s = new Date(startDate)
    s.setHours(0, 0, 0, 0)
    if (d < s) return false
  }
  if (endDate) {
    const e = new Date(endDate)
    e.setHours(23, 59, 59, 999)
    if (d > e) return false
  }
  return true
}

// ── Component ────────────────────────────────────────────────────────────

interface DateRangeFilterProps {
  startDate: string
  endDate: string
  onStartDateChange: (v: string) => void
  onEndDateChange: (v: string) => void
  onPreset: (days: number) => void
  /** Label shown on the trigger button. Defaults to "Date range". */
  label?: string
}

export function DateRangeFilter({
  startDate,
  endDate,
  onStartDateChange,
  onEndDateChange,
  onPreset,
  label = "Date range",
}: DateRangeFilterProps) {
  const presetLabel = getPresetLabel(startDate, endDate)
  const hasDateFilter = Boolean(startDate || endDate)

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="gap-1.5">
          <Calendar className="size-3.5" />
          {presetLabel ?? label}
          {hasDateFilter && (
            <Badge
              variant="secondary"
              className="ml-1 size-5 justify-center rounded-full px-0 text-[10px]"
            >
              1
            </Badge>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-72 space-y-3 p-3">
        <div className="flex flex-wrap gap-1">
          {DATE_PRESETS.map((preset) => (
            <Button
              key={preset.label}
              variant={presetLabel === preset.label ? "secondary" : "ghost"}
              size="sm"
              className="h-7 text-xs"
              onClick={() => onPreset(preset.days)}
            >
              {preset.label}
            </Button>
          ))}
        </div>
        <div className="-mx-3 h-px bg-border" />
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <label className="w-12 text-xs text-muted-foreground">From</label>
            <Input
              type="date"
              className="h-8 text-xs"
              value={startDate}
              onChange={(e) => onStartDateChange(e.target.value)}
              aria-label="From date"
            />
          </div>
          <div className="flex items-center gap-2">
            <label className="w-12 text-xs text-muted-foreground">To</label>
            <Input
              type="date"
              className="h-8 text-xs"
              value={endDate}
              onChange={(e) => onEndDateChange(e.target.value)}
              aria-label="To date"
            />
          </div>
        </div>
        {hasDateFilter && (
          <>
            <div className="-mx-3 h-px bg-border" />
            <Button
              variant="ghost"
              size="sm"
              className="w-full justify-center text-xs"
              onClick={() => onPreset(-1)}
            >
              Clear dates
            </Button>
          </>
        )}
      </PopoverContent>
    </Popover>
  )
}
