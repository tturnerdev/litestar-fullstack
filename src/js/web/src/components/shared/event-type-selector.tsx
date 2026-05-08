import { AlertCircle, Loader2 } from "lucide-react"
import { useCallback, useMemo } from "react"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { useWebhookEventTypes } from "@/lib/api/hooks/webhooks"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface EventCategory {
  label: string
  events: { event: string; description: string }[]
}

interface EventTypeSelectorProps {
  selected: string[]
  onChange: (events: string[]) => void
  disabled?: boolean
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Derive a human-readable group label from a dotted event name.
 * e.g. "device.created" -> "Devices", "phone_number.updated" -> "Phone Numbers"
 */
function groupLabelFromEvent(event: string): string {
  const prefix = event.split(".")[0] ?? event
  return prefix
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ")
    .replace(/s?$/, "s") // pluralise: "Device" -> "Devices"
    .replace(/ss$/, "s") // fix double-s: "Devicess" -> "Devices"
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function EventTypeSelector({ selected, onChange, disabled }: EventTypeSelectorProps) {
  const { data: eventTypes, isLoading, isError } = useWebhookEventTypes()

  // Group event types by domain prefix
  const categories: EventCategory[] = useMemo(() => {
    if (!eventTypes?.length) return []
    const groups = new Map<string, { event: string; description: string }[]>()
    for (const et of eventTypes) {
      const prefix = et.event.split(".")[0] ?? et.event
      if (!groups.has(prefix)) {
        groups.set(prefix, [])
      }
      groups.get(prefix)?.push({ event: et.event, description: et.description })
    }
    return Array.from(groups.entries()).map(([prefix, events]) => ({
      label: groupLabelFromEvent(prefix),
      events,
    }))
  }, [eventTypes])

  const allEvents = useMemo(() => categories.flatMap((c) => c.events.map((e) => e.event)), [categories])

  // Handlers
  const toggleEvent = useCallback(
    (event: string) => {
      onChange(selected.includes(event) ? selected.filter((e) => e !== event) : [...selected, event])
    },
    [selected, onChange],
  )

  const selectAll = useCallback(() => {
    onChange([...allEvents])
  }, [allEvents, onChange])

  const clearAll = useCallback(() => {
    onChange([])
  }, [onChange])

  const toggleGroup = useCallback(
    (groupEvents: string[]) => {
      const allSelected = groupEvents.every((e) => selected.includes(e))
      if (allSelected) {
        // Deselect all in this group
        onChange(selected.filter((e) => !groupEvents.includes(e)))
      } else {
        // Select all in this group
        const merged = new Set([...selected, ...groupEvents])
        onChange(Array.from(merged))
      }
    },
    [selected, onChange],
  )

  // Loading state
  if (isLoading) {
    return (
      <div className="flex items-center gap-2 rounded-md border p-4 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading event types...
      </div>
    )
  }

  // Error state
  if (isError || !eventTypes) {
    return (
      <div className="flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/5 p-4 text-sm text-destructive">
        <AlertCircle className="h-4 w-4 shrink-0" />
        Failed to load event types. Try refreshing the page.
      </div>
    )
  }

  // Empty state (unlikely but defensive)
  if (categories.length === 0) {
    return <div className="rounded-md border p-4 text-sm text-muted-foreground">No event types available.</div>
  }

  return (
    <div className="space-y-2">
      {/* Global actions */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Button type="button" variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={selectAll} disabled={disabled}>
            Select all
          </Button>
          <Button type="button" variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={clearAll} disabled={disabled || selected.length === 0}>
            Clear
          </Button>
        </div>
        {selected.length > 0 && (
          <p className="text-xs text-muted-foreground">
            {selected.length} of {allEvents.length} selected
          </p>
        )}
      </div>

      <p className="text-xs text-muted-foreground">Select which events should trigger this webhook. If none are selected, all events will be sent.</p>

      {/* Grouped checkboxes */}
      <div className="space-y-3 rounded-md border p-4">
        {categories.map((category) => {
          const groupEventNames = category.events.map((e) => e.event)
          const selectedInGroup = groupEventNames.filter((e) => selected.includes(e)).length
          const allInGroupSelected = selectedInGroup === groupEventNames.length
          const someInGroupSelected = selectedInGroup > 0 && !allInGroupSelected

          return (
            <div key={category.label}>
              <div className="mb-1.5 flex items-center gap-2">
                <Checkbox
                  checked={allInGroupSelected}
                  indeterminate={someInGroupSelected}
                  onChange={() => toggleGroup(groupEventNames)}
                  disabled={disabled}
                  aria-label={`Select all ${category.label} events`}
                />
                <button
                  type="button"
                  className="text-xs font-medium text-muted-foreground uppercase tracking-wider hover:text-foreground transition-colors"
                  onClick={() => toggleGroup(groupEventNames)}
                  disabled={disabled}
                >
                  {category.label}
                  {selectedInGroup > 0 && (
                    <span className="ml-1.5 normal-case tracking-normal font-normal">
                      ({selectedInGroup}/{groupEventNames.length})
                    </span>
                  )}
                </button>
              </div>
              <div className="grid grid-cols-2 gap-1.5 pl-6">
                {category.events.map(({ event, description }) => (
                  <div key={event} className="flex items-start gap-2 text-sm hover:bg-muted/50 rounded px-2 py-1" title={description}>
                    <Checkbox checked={selected.includes(event)} onChange={() => toggleEvent(event)} disabled={disabled} className="mt-0.5" aria-label={event} />
                    <span className="min-w-0">
                      <span className="text-xs font-mono block">{event}</span>
                      <span className="text-[10px] text-muted-foreground block leading-tight">{description}</span>
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )
        })}
      </div>

      {selected.length > 0 && (
        <p className="text-xs text-muted-foreground">
          {selected.length} event{selected.length === 1 ? "" : "s"} selected
        </p>
      )}
    </div>
  )
}

export { EventTypeSelector }
