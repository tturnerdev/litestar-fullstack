import { useState } from "react"
import { createFileRoute } from "@tanstack/react-router"
import { Search } from "lucide-react"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useAdminSupportStats, useAdminTickets } from "@/lib/api/hooks/admin"

export const Route = createFileRoute("/_app/admin/support")({
  component: AdminSupportPage,
})

const PAGE_SIZE = 25

const priorityVariant: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
  low: "outline",
  medium: "secondary",
  high: "default",
  urgent: "destructive",
}

const statusLabel: Record<string, string> = {
  open: "Open",
  in_progress: "In progress",
  waiting_on_customer: "Waiting (customer)",
  waiting_on_support: "Waiting (support)",
  resolved: "Resolved",
  closed: "Closed",
}

const statusVariant: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
  open: "default",
  in_progress: "secondary",
  waiting_on_customer: "outline",
  waiting_on_support: "outline",
  resolved: "outline",
  closed: "outline",
}

function AdminSupportPage() {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState("")

  const { data: stats, isLoading: statsLoading } = useAdminSupportStats()
  const { data, isLoading } = useAdminTickets(page, PAGE_SIZE, search || undefined)

  const tickets = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const statCards = [
    { label: "Open tickets", value: stats?.open ?? 0 },
    { label: "In progress", value: stats?.inProgress ?? 0 },
    { label: "Resolved", value: stats?.resolved ?? 0 },
    { label: "Closed", value: stats?.closed ?? 0 },
  ]

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Administration" title="Support" description="Monitor support tickets and response metrics across the organization." breadcrumbs={<AdminBreadcrumbs />} />
      <AdminNav />

      <PageSection>
        {statsLoading ? (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <SkeletonCard key={i} />
            ))}
          </div>
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {statCards.map((item) => (
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
        )}
      </PageSection>

      <PageSection delay={0.1}>
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-4">
              <CardTitle>All tickets</CardTitle>
              <div className="relative max-w-sm">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search tickets..."
                  value={search}
                  onChange={(e) => {
                    setSearch(e.target.value)
                    setPage(1)
                  }}
                  className="pl-9"
                />
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Ticket #</TableHead>
                  <TableHead>Subject</TableHead>
                  <TableHead>Creator</TableHead>
                  <TableHead>Assigned to</TableHead>
                  <TableHead>Priority</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8">
                      <div className="flex items-center justify-center">
                        <div className="h-5 w-5 animate-spin rounded-full border-2 border-muted-foreground border-t-transparent" />
                      </div>
                    </TableCell>
                  </TableRow>
                ) : tickets.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center text-muted-foreground">
                      {search ? "No tickets match your search." : "No tickets found."}
                    </TableCell>
                  </TableRow>
                ) : (
                  tickets.map((ticket) => (
                    <TableRow key={ticket.id}>
                      <TableCell className="font-mono text-sm">{ticket.ticketNumber}</TableCell>
                      <TableCell className="font-medium">{ticket.subject}</TableCell>
                      <TableCell className="text-muted-foreground">{ticket.creatorEmail ?? "—"}</TableCell>
                      <TableCell className="text-muted-foreground">{ticket.assignedToEmail ?? "Unassigned"}</TableCell>
                      <TableCell>
                        <Badge variant={priorityVariant[ticket.priority] ?? "outline"}>{ticket.priority}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={statusVariant[ticket.status] ?? "outline"}>{statusLabel[ticket.status] ?? ticket.status}</Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground">{new Date(ticket.createdAt).toLocaleString()}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
            {totalPages > 1 && (
              <div className="flex items-center justify-between">
                <p className="text-xs text-muted-foreground">
                  Page {page} of {totalPages} ({total} total)
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
