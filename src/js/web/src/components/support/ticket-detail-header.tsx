import { useNavigate } from "@tanstack/react-router"
import { Calendar, ChevronDown, Lock, Tag, Trash2, Unlock, User } from "lucide-react"
import { useState } from "react"
import { TicketPriorityBadge } from "@/components/support/ticket-priority-badge"
import { TicketStatusBadge } from "@/components/support/ticket-status-badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Separator } from "@/components/ui/separator"
import type { Ticket } from "@/lib/api/hooks/support"
import { useCloseTicket, useDeleteTicket, useReopenTicket, useUpdateTicket } from "@/lib/api/hooks/support"

interface TicketDetailHeaderProps {
  ticket: Ticket
}

const categoryLabels: Record<string, string> = {
  billing: "Billing",
  technical: "Technical",
  account: "Account",
  device: "Device",
  voice: "Voice",
  fax: "Fax",
  general: "General",
}

const priorities = ["low", "medium", "high", "urgent"] as const

export function TicketDetailHeader({ ticket }: TicketDetailHeaderProps) {
  const navigate = useNavigate()
  const closeTicket = useCloseTicket(ticket.id)
  const reopenTicket = useReopenTicket(ticket.id)
  const updateTicket = useUpdateTicket(ticket.id)
  const deleteTicket = useDeleteTicket(ticket.id)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)

  const isClosed = ticket.status === "closed" || ticket.status === "resolved"

  return (
    <div className="flex flex-col gap-4 rounded-lg border border-border/60 bg-card/80 px-4 py-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
        <span className="font-mono text-xs text-muted-foreground">{ticket.ticketNumber}</span>
        <Separator orientation="vertical" className="h-4" />
        <TicketStatusBadge status={ticket.status} />
        <Separator orientation="vertical" className="h-4" />
        <TicketPriorityBadge priority={ticket.priority} />
        {ticket.category && (
          <>
            <Separator orientation="vertical" className="h-4" />
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Tag className="h-3.5 w-3.5" />
              <span>{categoryLabels[ticket.category] ?? ticket.category}</span>
            </div>
          </>
        )}
        {ticket.assignedTo && (
          <>
            <Separator orientation="vertical" className="h-4" />
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <User className="h-3.5 w-3.5" />
              <span>{ticket.assignedTo.name ?? ticket.assignedTo.email}</span>
            </div>
          </>
        )}
        <Separator orientation="vertical" className="h-4" />
        <div className="flex items-center gap-1.5 text-muted-foreground">
          <Calendar className="h-3.5 w-3.5" />
          <span>
            {ticket.createdAt ? new Date(ticket.createdAt).toLocaleDateString() : ""}
          </span>
        </div>

        <div className="ml-auto flex items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" className="h-7 text-xs">
                Priority
                <ChevronDown className="ml-1 h-3 w-3" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Change Priority</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {priorities.map((p) => (
                <DropdownMenuItem
                  key={p}
                  onClick={() => updateTicket.mutate({ priority: p })}
                  disabled={ticket.priority === p}
                >
                  <TicketPriorityBadge priority={p} />
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>

          {isClosed ? (
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-xs"
              onClick={() => reopenTicket.mutate()}
              disabled={reopenTicket.isPending}
            >
              <Unlock className="mr-1.5 h-3 w-3" />
              Reopen
            </Button>
          ) : (
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-xs"
              onClick={() => closeTicket.mutate()}
              disabled={closeTicket.isPending}
            >
              <Lock className="mr-1.5 h-3 w-3" />
              Close
            </Button>
          )}

          <Button
            size="sm"
            variant="outline"
            className="h-7 text-xs text-destructive hover:bg-destructive/10"
            onClick={() => setShowDeleteDialog(true)}
          >
            <Trash2 className="mr-1.5 h-3 w-3" />
            Delete
          </Button>
        </div>
      </div>

      <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete ticket</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete ticket{" "}
              <span className="font-medium text-foreground">{ticket.ticketNumber}</span>? This will
              permanently remove the ticket and all of its messages. This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDeleteDialog(false)} disabled={deleteTicket.isPending}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={deleteTicket.isPending}
              onClick={() => {
                deleteTicket.mutate(undefined, {
                  onSuccess: () => {
                    setShowDeleteDialog(false)
                    navigate({ to: "/support" })
                  },
                })
              }}
            >
              {deleteTicket.isPending ? "Deleting..." : "Delete ticket"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
