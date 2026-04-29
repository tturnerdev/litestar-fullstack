import { useState } from "react"
import { createFileRoute } from "@tanstack/react-router"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

export const Route = createFileRoute("/_app/admin/fax")({
  component: AdminFaxPage,
})

// Placeholder data until backend aggregation endpoints are available
const stats = [
  { label: "Total fax numbers", value: 0 },
  { label: "Sent today", value: 0 },
  { label: "Queued messages", value: 0 },
  { label: "Failed messages", value: 0 },
]

interface FaxActivityRow {
  id: string
  direction: "inbound" | "outbound"
  faxNumber: string
  remoteNumber: string
  pages: number
  status: "completed" | "sending" | "queued" | "failed"
  teamName: string
  createdAt: string
}

// Placeholder -- will be replaced by API data
const placeholderFaxActivity: FaxActivityRow[] = []

const PAGE_SIZE = 25

const statusVariant: Record<FaxActivityRow["status"], "default" | "secondary" | "outline" | "destructive"> = {
  completed: "default",
  sending: "secondary",
  queued: "outline",
  failed: "destructive",
}

function AdminFaxPage() {
  const [page, setPage] = useState(1)

  // TODO: replace with admin API hooks once backend endpoints exist
  const faxActivity = placeholderFaxActivity
  const total = faxActivity.length
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const paged = faxActivity.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Administration" title="Fax" description="Monitor fax numbers, messages, and delivery across the organization." />
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
            <CardTitle>Recent fax activity</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Direction</TableHead>
                  <TableHead>Fax number</TableHead>
                  <TableHead>Remote number</TableHead>
                  <TableHead>Pages</TableHead>
                  <TableHead>Team</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Date</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {paged.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center text-muted-foreground">
                      No fax activity found. Activity will appear here once the fax backend is connected.
                    </TableCell>
                  </TableRow>
                )}
                {paged.map((fax) => (
                  <TableRow key={fax.id}>
                    <TableCell>
                      <Badge variant={fax.direction === "inbound" ? "outline" : "secondary"}>{fax.direction}</Badge>
                    </TableCell>
                    <TableCell className="font-mono font-medium">{fax.faxNumber}</TableCell>
                    <TableCell className="font-mono text-muted-foreground">{fax.remoteNumber}</TableCell>
                    <TableCell className="text-muted-foreground">{fax.pages}</TableCell>
                    <TableCell className="text-muted-foreground">{fax.teamName}</TableCell>
                    <TableCell>
                      <Badge variant={statusVariant[fax.status]}>{fax.status}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{new Date(fax.createdAt).toLocaleString()}</TableCell>
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
