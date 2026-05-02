import type { LucideIcon } from "lucide-react"
import { AlertTriangle, ArrowDown, ArrowUp, Minus } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { cn } from "@/lib/utils"

const priorityConfig: Record<string, { label: string; description: string; className: string; icon: LucideIcon; pulse?: boolean }> = {
  low: {
    label: "Low",
    description: "Low: Can be addressed when convenient",
    className: "border-zinc-500/30 bg-zinc-500/10 text-zinc-700 dark:text-zinc-400",
    icon: ArrowDown,
  },
  medium: {
    label: "Medium",
    description: "Medium: Should be addressed in a timely manner",
    className: "border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-400",
    icon: Minus,
  },
  high: {
    label: "High",
    description: "High: Needs prompt attention",
    className: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400",
    icon: ArrowUp,
  },
  urgent: {
    label: "Urgent",
    description: "Urgent: Requires immediate attention",
    className: "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-400",
    icon: AlertTriangle,
    pulse: true,
  },
}

interface TicketPriorityBadgeProps {
  priority: string
  size?: "sm" | "default"
}

export function TicketPriorityBadge({ priority, size = "default" }: TicketPriorityBadgeProps) {
  const config = priorityConfig[priority] ?? {
    label: priority,
    description: priority,
    className: "",
    icon: Minus,
  }
  const Icon = config.icon

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge variant="outline" className={cn("text-xs gap-1", config.className, config.pulse && "animate-pulse", size === "sm" && "px-1.5")}>
          <Icon className="h-3 w-3 shrink-0" />
          {size === "default" && <span>{config.label}</span>}
        </Badge>
      </TooltipTrigger>
      <TooltipContent>{config.description}</TooltipContent>
    </Tooltip>
  )
}
