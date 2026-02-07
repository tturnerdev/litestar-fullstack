import { Link } from "@tanstack/react-router"
import { LifeBuoy } from "lucide-react"
import { useState } from "react"
import { TicketPriorityBadge } from "@/components/support/ticket-priority-badge"
import { TicketStatusBadge } from "@/components/support/ticket-status-badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useTickets } from "@/lib/api/hooks/support"

const PAGE_SIZE = 25

export function TicketTable() {
  const [page, setPage] = useState(1)
  const { data, isLoading, isError } = useTickets(page, PAGE_SIZE)

  if (isLoading) {
    return <SkeletonTable rows={6} />
  }

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Tickets</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">We could not load tickets.</CardContent>
      </Card>
    )
  }

  if (data.items.length === 0 && page === 1) {
    return (
      <Card className="border-dashed border-2">
        <CardContent className="py-16 text-center space-y-6">
          <div className="mx-auto w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
            <LifeBuoy className="h-8 w-8 text-primary" />
          </div>
          <div className="space-y-2">
            <h3 className="text-lg font-semibold">No tickets yet</h3>
            <p className="text-muted-foreground text-sm max-w-md mx-auto">
              Create a support ticket to get help from our team.
            </p>
          </div>
          <Button asChild size="lg">
            <Link to="/support/new">Create ticket</Link>
          </Button>
        </CardContent>
      </Card>
    )
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE))

  return (
    <Card>
      <CardHeader>
        <CardTitle>Tickets</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Ticket</TableHead>
              <TableHead>Subject</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Priority</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.items.map((ticket) => (
              <TableRow key={ticket.id}>
                <TableCell className="font-mono text-xs text-muted-foreground">{ticket.ticketNumber}</TableCell>
                <TableCell>
                  <Link
                    to="/support/$ticketId"
                    params={{ ticketId: ticket.id }}
                    className="font-medium hover:underline"
                  >
                    {ticket.subject}
                  </Link>
                  {ticket.latestMessagePreview && (
                    <p className="text-xs text-muted-foreground line-clamp-1 mt-0.5">{ticket.latestMessagePreview}</p>
                  )}
                </TableCell>
                <TableCell>
                  <TicketStatusBadge status={ticket.status} />
                </TableCell>
                <TableCell>
                  <TicketPriorityBadge priority={ticket.priority} />
                </TableCell>
                <TableCell className="text-muted-foreground text-sm">
                  {ticket.createdAt ? new Date(ticket.createdAt).toLocaleDateString() : "—"}
                </TableCell>
                <TableCell className="text-right">
                  <Button asChild variant="outline" size="sm">
                    <Link to="/support/$ticketId" params={{ ticketId: ticket.id }}>
                      View
                    </Link>
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {totalPages > 1 && (
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              Page {page} of {totalPages}
            </p>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>
                Previous
              </Button>
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>
                Next
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
