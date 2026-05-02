import { RefreshCw } from "lucide-react"
import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { cn } from "@/lib/utils"

function formatLastUpdated(timestamp: number): string {
  const now = Date.now()
  const diffMs = now - timestamp
  const diffSec = Math.floor(diffMs / 1000)
  const diffMin = Math.floor(diffSec / 60)
  const diffHr = Math.floor(diffMin / 60)

  if (diffSec < 10) return "just now"
  if (diffSec < 60) return `${diffSec}s ago`
  if (diffMin < 60) return `${diffMin}m ago`
  if (diffHr < 24) return `${diffHr}h ago`
  return new Date(timestamp).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
}

export function DataFreshness({ dataUpdatedAt, onRefresh, isRefreshing }: { dataUpdatedAt: number | undefined; onRefresh: () => void; isRefreshing: boolean }) {
  const [label, setLabel] = useState("")

  useEffect(() => {
    if (!dataUpdatedAt) return
    const update = () => setLabel(formatLastUpdated(dataUpdatedAt))
    update()
    const interval = setInterval(update, 10_000)
    return () => clearInterval(interval)
  }, [dataUpdatedAt])

  if (!dataUpdatedAt) return null

  return (
    <div className="flex items-center gap-1.5">
      {label && <span className="text-xs text-muted-foreground">Updated {label}</span>}
      <Tooltip>
        <TooltipTrigger asChild>
          <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground" onClick={onRefresh} disabled={isRefreshing}>
            <RefreshCw className={cn("h-3.5 w-3.5", isRefreshing && "animate-spin")} />
            <span className="sr-only">Refresh data</span>
          </Button>
        </TooltipTrigger>
        <TooltipContent>Refresh data</TooltipContent>
      </Tooltip>
    </div>
  )
}
