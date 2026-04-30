import { Link } from "@tanstack/react-router"
import { Bug, ChevronRight, Clock, HelpCircle, Lightbulb, MessageSquare, Wrench } from "lucide-react"
import { TicketPriorityBadge } from "@/components/support/ticket-priority-badge"
import { TicketStatusBadge } from "@/components/support/ticket-status-badge"
import type { Ticket } from "@/lib/api/hooks/support"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { formatRelativeTimeShort } from "@/lib/date-utils"
import { cn } from "@/lib/utils"

const categoryConfig: Record<string, { icon: typeof HelpCircle; label: string }> = {
  general: { icon: HelpCircle, label: "General" },
  bug: { icon: Bug, label: "Bug" },
  feature_request: { icon: Lightbulb, label: "Feature" },
  technical: { icon: Wrench, label: "Technical" },
  billing: { icon: MessageSquare, label: "Billing" },
}

interface TicketListItemProps {
  ticket: Ticket
}

export function TicketListItem({ ticket }: TicketListItemProps) {
  const isUnread = !ticket.isReadByUser
  const category = ticket.category ? categoryConfig[ticket.category] : null
  const CategoryIcon = category?.icon ?? HelpCircle
  const isSlaWarning = (ticket.priority === "urgent" || ticket.priority === "high") && ticket.status === "open"

  return (
    <Link
      to="/support/$ticketId"
      params={{ ticketId: ticket.id }}
      className={cn(
        "group flex items-center gap-4 rounded-lg border bg-card/80 px-4 py-3 transition-all hover:border-border hover:bg-card hover:shadow-sm",
        isUnread
          ? "border-l-2 border-l-primary border-border/60"
          : "border-border/60",
      )}
    >
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-muted/60 text-muted-foreground">
        <CategoryIcon className="h-4 w-4" />
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs text-muted-foreground">{ticket.ticketNumber}</span>
          {isUnread && (
            <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
          )}
          <Tooltip>
            <TooltipTrigger asChild>
              <span className={cn("truncate text-sm font-medium", isUnread && "font-semibold")}>
                {ticket.subject}
              </span>
            </TooltipTrigger>
            <TooltipContent>{ticket.subject}</TooltipContent>
          </Tooltip>
        </div>
        {ticket.latestMessagePreview && (
          <p className="mt-0.5 line-clamp-1 text-xs text-muted-foreground">
            {ticket.latestMessagePreview}
          </p>
        )}
      </div>

      <div className="flex shrink-0 items-center gap-2">
        {isSlaWarning && (
          <Clock
            className={cn(
              "h-4 w-4",
              ticket.priority === "urgent" ? "text-red-500" : "text-amber-500",
            )}
          />
        )}
        {ticket.messageCount > 0 && (
          <span className="flex items-center gap-1 text-xs text-muted-foreground">
            <MessageSquare className="h-3.5 w-3.5" />
            {ticket.messageCount}
          </span>
        )}
        <TicketStatusBadge status={ticket.status} />
        <TicketPriorityBadge priority={ticket.priority} />
        <span className="w-16 text-right text-xs text-muted-foreground">
          {formatRelativeTimeShort(ticket.updatedAt ?? ticket.createdAt)}
        </span>
        <ChevronRight className="h-4 w-4 text-muted-foreground/0 transition-all group-hover:text-muted-foreground" />
      </div>
    </Link>
  )
}
