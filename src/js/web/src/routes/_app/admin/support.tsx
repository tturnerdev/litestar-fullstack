import { useState } from "react"
import { createFileRoute } from "@tanstack/react-router"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

export const Route = createFileRoute("/_app/admin/support")({
  component: AdminSupportPage,
})

// Placeholder data until backend aggregation endpoints are available
const stats = [
  { label: "Open tickets", value: 0 },
  { label: "Tickets today", value: 0 },
  { label: "Avg. response time", value: "--" },
  { label: "Unassigned tickets", value: 0 },
]

interface TicketRow {
  id: string
  subject: string
  requesterName: string
  teamName: string
  assigneeName: string | null
  priority: "low" | "medium" | "high" | "urgent"
  status: "open" | "in_progress" | "waiting" | "resolved" | "closed"
  createdAt: string
}

// Placeholder -- will be replaced by API data
const placeholderTickets: TicketRow[] = []

const PAGE_SIZE = 25

const priorityVariant: Record<TicketRow["priority"], "default" | "secondary" | "outline" | "destructive"> = {
  low: "outline",
  medium: "secondary",
  high: "default",
  urgent: "destructive",
}

const statusLabel: Record<TicketRow["status"], string> = {
  open: "Open",
  in_progress: "In progress",
  waiting: "Waiting",
  resolved: "Resolved",
  closed: "Closed",
}

const statusVariant: Record<TicketRow["status"], "default" | "secondary" | "outline" | "destructive"> = {
  open: "default",
  in_progress: "secondary",
  waiting: "outline",
  resolved: "outline",
  closed: "outline",
}

function AdminSupportPage() {
  const [page, setPage] = useState(1)

  // TODO: replace with admin API hooks once backend endpoints exist
  const tickets = placeholderTickets
  const total = tickets.length
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const paged = tickets.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Administration" title="Support" description="Monitor support tickets and response metrics across the organization." />
      <AdminNav />

      <PageSection>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {stats.map((item) => (
            <Card key={item.label}>
              <CardHeader>
                <CardTitle className="text-sm text-muted-foreground">{item.label}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-semibold">{item.value}</div>
              </CardContent>
            </Card>
          ))}
        </div>
      </PageSection>

      <PageSection delay={0.1}>
        <Card>
          <CardHeader>
            <CardTitle>Open tickets</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Subject</TableHead>
                  <TableHead>Requester</TableHead>
                  <TableHead>Team</TableHead>
                  <TableHead>Assigned to</TableHead>
                  <TableHead>Priority</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {paged.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center text-muted-foreground">
                      No tickets found. Tickets will appear here once the support backend is connected.
                    </TableCell>
                  </TableRow>
                )}
                {paged.map((ticket) => (
                  <TableRow key={ticket.id}>
                    <TableCell className="font-medium">{ticket.subject}</TableCell>
                    <TableCell className="text-muted-foreground">{ticket.requesterName}</TableCell>
                    <TableCell className="text-muted-foreground">{ticket.teamName}</TableCell>
                    <TableCell className="text-muted-foreground">{ticket.assigneeName ?? "Unassigned"}</TableCell>
                    <TableCell>
                      <Badge variant={priorityVariant[ticket.priority]}>{ticket.priority}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={statusVariant[ticket.status]}>{statusLabel[ticket.status]}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{new Date(ticket.createdAt).toLocaleString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {total > PAGE_SIZE && (
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
      </PageSection>
    </PageContainer>
  )
}
