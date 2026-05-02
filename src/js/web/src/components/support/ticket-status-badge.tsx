import type { LucideIcon } from "lucide-react"
import { CheckCircle, Circle, Clock, Headphones, User, XCircle } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { cn } from "@/lib/utils"

const statusConfig: Record<string, { label: string; description: string; className: string; dotColor: string; icon: LucideIcon }> = {
  open: {
    label: "Open",
    description: "Open: Awaiting initial review by support",
    className: "border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-400",
    dotColor: "bg-blue-500",
    icon: Circle,
  },
  in_progress: {
    label: "In Progress",
    description: "In Progress: Currently being worked on by support",
    className: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400",
    dotColor: "bg-amber-500",
    icon: Clock,
  },
  waiting_on_customer: {
    label: "Waiting on Customer",
    description: "Waiting on Customer: Needs a response from the customer",
    className: "border-purple-500/30 bg-purple-500/10 text-purple-700 dark:text-purple-400",
    dotColor: "bg-purple-500",
    icon: User,
  },
  waiting_on_support: {
    label: "Waiting on Support",
    description: "Waiting on Support: Queued for support team review",
    className: "border-indigo-500/30 bg-indigo-500/10 text-indigo-700 dark:text-indigo-400",
    dotColor: "bg-indigo-500",
    icon: Headphones,
  },
  resolved: {
    label: "Resolved",
    description: "Resolved: Issue has been addressed successfully",
    className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
    dotColor: "bg-emerald-500",
    icon: CheckCircle,
  },
  closed: {
    label: "Closed",
    description: "Closed: Ticket has been finalized",
    className: "border-zinc-500/30 bg-zinc-500/10 text-zinc-700 dark:text-zinc-400",
    dotColor: "bg-zinc-500",
    icon: XCircle,
  },
}

export function TicketStatusBadge({ status }: { status: string }) {
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
        <Badge variant="outline" className={cn("animate-in fade-in-0 zoom-in-95 text-xs gap-1.5 duration-200", config.className)}>
          <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", config.dotColor)} />
          <Icon className="h-3 w-3 shrink-0" />
          <span>{config.label}</span>
        </Badge>
      </TooltipTrigger>
      <TooltipContent>{config.description}</TooltipContent>
    </Tooltip>
  )
}
