import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

const priorityConfig: Record<string, { label: string; className: string }> = {
  low: {
    label: "Low",
    className: "border-zinc-500/30 bg-zinc-500/10 text-zinc-700 dark:text-zinc-400",
  },
  medium: {
    label: "Medium",
    className: "border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-400",
  },
  high: {
    label: "High",
    className: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400",
  },
  urgent: {
    label: "Urgent",
    className: "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-400",
  },
}

export function TicketPriorityBadge({ priority }: { priority: string }) {
  const config = priorityConfig[priority] ?? { label: priority, className: "" }
  return (
    <Badge variant="outline" className={cn("text-xs", config.className)}>
      {config.label}
    </Badge>
  )
}
