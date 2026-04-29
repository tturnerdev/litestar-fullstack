import { useNavigate } from "@tanstack/react-router"
import {
  Calendar,
  ChevronDown,
  Clock,
  Lock,
  Mail,
  Tag,
  Trash2,
  Unlock,
  User,
  Users,
} from "lucide-react"
import { useState } from "react"
import { TicketPriorityBadge } from "@/components/support/ticket-priority-badge"
import { TicketStatusBadge } from "@/components/support/ticket-status-badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
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
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
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

function formatRelativeTime(dateStr: string | null | undefined): string {
  if (!dateStr) return "--"
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)
  const diffMin = Math.floor(diffSec / 60)
  const diffHr = Math.floor(diffMin / 60)
  const diffDays = Math.floor(diffHr / 24)

  if (diffSec < 60) return "just now"
  if (diffMin < 60) return `${diffMin}m ago`
  if (diffHr < 24) return `${diffHr}h ago`
  if (diffDays < 7) return `${diffDays}d ago`
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: date.getFullYear() !== now.getFullYear() ? "numeric" : undefined })
}

export function TicketDetailHeader({ ticket }: TicketDetailHeaderProps) {
  const navigate = useNavigate()
  const closeTicket = useCloseTicket(ticket.id)
  const reopenTicket = useReopenTicket(ticket.id)
  const updateTicket = useUpdateTicket(ticket.id)
  const deleteTicket = useDeleteTicket(ticket.id)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)

  const isClosed = ticket.status === "closed" || ticket.status === "resolved"

  return (
    <Card className="border-border/60 bg-card/80">
      <CardContent className="py-4">
        {/* Action bar */}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
          <span className="font-mono text-xs text-muted-foreground">{ticket.ticketNumber}</span>
          <Separator orientation="vertical" className="h-4" />
          <TicketStatusBadge status={ticket.status} />
          <Separator orientation="vertical" className="h-4" />
          <TicketPriorityBadge priority={ticket.priority} />

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

        <Separator className="my-4" />

        {/* Metadata grid */}
        <div className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
          {/* Reporter */}
          <div className="flex items-start gap-2.5">
            <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
              <User className="h-3.5 w-3.5 text-muted-foreground" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Reporter
              </p>
              <p className="mt-0.5 truncate font-medium">
                {ticket.user?.name ?? ticket.user?.email ?? "Unknown"}
              </p>
              {ticket.user?.name && ticket.user?.email && (
                <p className="truncate text-xs text-muted-foreground">{ticket.user.email}</p>
              )}
            </div>
          </div>

          {/* Assigned to */}
          <div className="flex items-start gap-2.5">
            <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
              <Users className="h-3.5 w-3.5 text-muted-foreground" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Assigned To
              </p>
              {ticket.assignedTo ? (
                <>
                  <p className="mt-0.5 truncate font-medium">
                    {ticket.assignedTo.name ?? ticket.assignedTo.email}
                  </p>
                  {ticket.assignedTo.name && ticket.assignedTo.email && (
                    <p className="truncate text-xs text-muted-foreground">
                      {ticket.assignedTo.email}
                    </p>
                  )}
                </>
              ) : (
                <p className="mt-0.5 text-muted-foreground/70">Unassigned</p>
              )}
            </div>
          </div>

          {/* Category */}
          <div className="flex items-start gap-2.5">
            <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
              <Tag className="h-3.5 w-3.5 text-muted-foreground" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Category
              </p>
              <p className="mt-0.5 font-medium">
                {ticket.category ? (categoryLabels[ticket.category] ?? ticket.category) : "None"}
              </p>
            </div>
          </div>

          {/* Messages */}
          <div className="flex items-start gap-2.5">
            <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
              <Mail className="h-3.5 w-3.5 text-muted-foreground" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Messages
              </p>
              <p className="mt-0.5 font-medium">{ticket.messageCount}</p>
            </div>
          </div>
        </div>

        <Separator className="my-4" />

        {/* Timestamps row */}
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs text-muted-foreground">
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="flex items-center gap-1.5 cursor-default">
                <Calendar className="h-3.5 w-3.5" />
                <span>Created {formatRelativeTime(ticket.createdAt)}</span>
              </div>
            </TooltipTrigger>
            <TooltipContent>
              {ticket.createdAt ? new Date(ticket.createdAt).toLocaleString() : "--"}
            </TooltipContent>
          </Tooltip>

          {ticket.updatedAt && ticket.updatedAt !== ticket.createdAt && (
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center gap-1.5 cursor-default">
                  <Clock className="h-3.5 w-3.5" />
                  <span>Updated {formatRelativeTime(ticket.updatedAt)}</span>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                {new Date(ticket.updatedAt).toLocaleString()}
              </TooltipContent>
            </Tooltip>
          )}

          {ticket.closedAt && (
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center gap-1.5 cursor-default">
                  <Lock className="h-3.5 w-3.5" />
                  <span>Closed {formatRelativeTime(ticket.closedAt)}</span>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                {new Date(ticket.closedAt).toLocaleString()}
              </TooltipContent>
            </Tooltip>
          )}

          {ticket.resolvedAt && (
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center gap-1.5 cursor-default">
                  <Lock className="h-3.5 w-3.5" />
                  <span>Resolved {formatRelativeTime(ticket.resolvedAt)}</span>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                {new Date(ticket.resolvedAt).toLocaleString()}
              </TooltipContent>
            </Tooltip>
          )}
        </div>
      </CardContent>

      {/* Delete confirmation */}
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
    </Card>
  )
}
