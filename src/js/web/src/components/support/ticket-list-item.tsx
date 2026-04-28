import { Link } from "@tanstack/react-router"
import { TicketPriorityBadge } from "@/components/support/ticket-priority-badge"
import { TicketStatusBadge } from "@/components/support/ticket-status-badge"
import type { Ticket } from "@/lib/api/hooks/support"
import { cn } from "@/lib/utils"

interface TicketListItemProps {
  ticket: Ticket
}

export function TicketListItem({ ticket }: TicketListItemProps) {
  const isUnread = !ticket.isReadByUser

  return (
    <Link
      to="/support/$ticketId"
      params={{ ticketId: ticket.id }}
      className={cn(
        "group flex items-center gap-4 rounded-lg border border-border/60 bg-card/80 px-4 py-3 transition-all hover:border-border hover:bg-card hover:shadow-sm",
        isUnread && "border-primary/30 bg-primary/[0.02]",
      )}
    >
      {isUnread && (
        <div className="h-2 w-2 shrink-0 rounded-full bg-primary" />
      )}
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs text-muted-foreground">{ticket.ticketNumber}</span>
          <span className={cn("truncate text-sm font-medium", isUnread && "font-semibold")}>
            {ticket.subject}
          </span>
        </div>
        {ticket.latestMessagePreview && (
          <p className="mt-0.5 line-clamp-1 text-xs text-muted-foreground">
            {ticket.latestMessagePreview}
          </p>
        )}
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <TicketStatusBadge status={ticket.status} />
        <TicketPriorityBadge priority={ticket.priority} />
        <span className="text-xs text-muted-foreground">
          {ticket.updatedAt
            ? new Date(ticket.updatedAt).toLocaleDateString()
            : ticket.createdAt
              ? new Date(ticket.createdAt).toLocaleDateString()
              : ""}
        </span>
      </div>
    </Link>
  )
}
