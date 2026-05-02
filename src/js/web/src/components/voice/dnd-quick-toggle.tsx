import { BellOff, BellRing, Loader2 } from "lucide-react"
import { useCallback } from "react"
import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDndSettings, useToggleDnd } from "@/lib/api/hooks/voice"
import { cn } from "@/lib/utils"

const DND_MODE_LABELS: Record<string, string> = {
  always: "Do Not Disturb",
  scheduled: "Scheduled DND",
  off: "Off",
}

interface DndQuickToggleProps {
  extensionId: string
  variant?: "default" | "ghost" | "outline" | "destructive"
  size?: "default" | "sm" | "lg" | "icon"
  showLabel?: boolean
  compact?: boolean
}

export function DndQuickToggle({ extensionId, variant = "ghost", size = "sm", showLabel = false, compact = false }: DndQuickToggleProps) {
  const { data, isLoading } = useDndSettings(extensionId)
  const toggleMutation = useToggleDnd(extensionId)

  const handleToggle = useCallback(() => {
    toggleMutation.mutate()
  }, [toggleMutation])

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "d" && !e.metaKey && !e.ctrlKey && !e.altKey && !toggleMutation.isPending) {
        e.preventDefault()
        handleToggle()
      }
    },
    [handleToggle, toggleMutation.isPending],
  )

  if (isLoading || !data) return null

  const isEnabled = data.isEnabled
  const isPending = toggleMutation.isPending

  const resolvedSize = compact ? "icon" : size
  const modeLabel = data.mode ? DND_MODE_LABELS[data.mode] : undefined

  const tooltipText = isEnabled ? `Disable DND${modeLabel ? ` (${modeLabel})` : ""}` : "Enable Do Not Disturb"

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant={isEnabled && !isPending ? "destructive" : variant}
          size={resolvedSize}
          onClick={handleToggle}
          onKeyDown={handleKeyDown}
          disabled={isPending}
          className={cn("relative", compact && "h-7 w-7", isEnabled && variant !== "destructive" && !isPending && "bg-destructive/10 hover:bg-destructive/20")}
        >
          {/* Pulsing red dot when DND is enabled */}
          {isEnabled && !isPending && (
            <span className="absolute -right-0.5 -top-0.5 flex h-2.5 w-2.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-75" />
              <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-red-500" />
            </span>
          )}

          {/* Icon with transition — spinner when pending, bell icons otherwise */}
          {isPending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <span className="transition-opacity duration-200">{isEnabled ? <BellOff className="h-4 w-4" /> : <BellRing className="h-4 w-4" />}</span>
          )}

          {showLabel && !compact && <span className="ml-2">{isEnabled ? "DND On" : "DND Off"}</span>}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{tooltipText}</TooltipContent>
    </Tooltip>
  )
}
