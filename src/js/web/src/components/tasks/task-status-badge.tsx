import type { LucideIcon } from "lucide-react"
import { Ban, CheckCircle, Circle, Loader2, Clock, XCircle } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { cn } from "@/lib/utils"

const statusConfig: Record<
  string,
  { label: string; description: string; className: string; dotColor: string; icon: LucideIcon }
> = {
  pending: {
    label: "Pending",
    description: "Pending: Task is queued and waiting to start",
    className: "border-yellow-500/30 bg-yellow-500/10 text-yellow-700 dark:text-yellow-400",
    dotColor: "bg-yellow-500",
    icon: Clock,
  },
  running: {
    label: "Running",
    description: "Running: Task is currently being processed",
    className: "border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-400",
    dotColor: "bg-blue-500",
    icon: Loader2,
  },
  completed: {
    label: "Completed",
    description: "Completed: Task finished successfully",
    className: "border-green-500/30 bg-green-500/10 text-green-700 dark:text-green-400",
    dotColor: "bg-green-500",
    icon: CheckCircle,
  },
  failed: {
    label: "Failed",
    description: "Failed: Task encountered an error",
    className: "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-400",
    dotColor: "bg-red-500",
    icon: XCircle,
  },
  cancelled: {
    label: "Cancelled",
    description: "Cancelled: Task was manually cancelled",
    className: "border-zinc-500/30 bg-zinc-500/10 text-zinc-700 dark:text-zinc-400",
    dotColor: "bg-zinc-500",
    icon: Ban,
  },
}

export function TaskStatusBadge({ status }: { status: string }) {
  const config = statusConfig[status] ?? {
    label: status,
    description: status,
    className: "",
    dotColor: "bg-zinc-500",
    icon: Circle,
  }
  const Icon = config.icon

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge
          variant="outline"
          className={cn(
            "animate-in fade-in-0 zoom-in-95 text-xs gap-1.5 duration-200",
            config.className,
          )}
        >
          <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", config.dotColor)} />
          <Icon className={cn("h-3 w-3 shrink-0", status === "running" && "animate-spin")} />
          <span>{config.label}</span>
        </Badge>
      </TooltipTrigger>
      <TooltipContent>{config.description}</TooltipContent>
    </Tooltip>
  )
}
