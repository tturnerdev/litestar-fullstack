import { useState } from "react"
import { createFileRoute } from "@tanstack/react-router"
import { Search } from "lucide-react"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useAdminFaxMessages, useAdminFaxNumbers, useAdminFaxStats } from "@/lib/api/hooks/admin"

export const Route = createFileRoute("/_app/admin/fax")({
  component: AdminFaxPage,
})

const PAGE_SIZE = 25

const statusVariant: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
  completed: "default",
  delivered: "default",
  sending: "secondary",
  queued: "outline",
  failed: "destructive",
}

function AdminFaxPage() {
  const [numberPage, setNumberPage] = useState(1)
  const [numberSearch, setNumberSearch] = useState("")

  const { data: stats, isLoading: statsLoading } = useAdminFaxStats()
  const { data: numberData, isLoading: numbersLoading } = useAdminFaxNumbers(numberPage, PAGE_SIZE, numberSearch || undefined)
  const { data: messages, isLoading: messagesLoading } = useAdminFaxMessages()

  const faxNumbers = numberData?.items ?? []
  const numberTotal = numberData?.total ?? 0
  const numberTotalPages = Math.max(1, Math.ceil(numberTotal / PAGE_SIZE))

  const faxMessages = Array.isArray(messages) ? messages : []

  const statCards = [
    { label: "Fax numbers", value: stats?.totalNumbers ?? 0 },
    { label: "Active numbers", value: stats?.activeNumbers ?? 0 },
    { label: "Messages today", value: stats?.messagesToday ?? 0 },
    { label: "Failed today", value: stats?.failedToday ?? 0 },
  ]

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Administration" title="Fax" description="Monitor fax numbers, messages, and delivery across the organization." />
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
              <CardTitle>Fax numbers</CardTitle>
              <div className="relative max-w-sm">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search numbers..."
                  value={numberSearch}
                  onChange={(e) => {
                    setNumberSearch(e.target.value)
                    setNumberPage(1)
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
                  <TableHead>Number</TableHead>
                  <TableHead>Label</TableHead>
                  <TableHead>Team</TableHead>
                  <TableHead>Owner</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {numbersLoading ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8">
                      <div className="flex items-center justify-center">
                        <div className="h-5 w-5 animate-spin rounded-full border-2 border-muted-foreground border-t-transparent" />
                      </div>
                    </TableCell>
                  </TableRow>
                ) : faxNumbers.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center text-muted-foreground">
                      {numberSearch ? "No numbers match your search." : "No fax numbers found."}
                    </TableCell>
                  </TableRow>
                ) : (
                  faxNumbers.map((fn) => (
                    <TableRow key={fn.id}>
                      <TableCell className="font-mono font-medium">{fn.number}</TableCell>
                      <TableCell className="text-muted-foreground">{fn.label ?? "—"}</TableCell>
                      <TableCell className="text-muted-foreground">{fn.teamName ?? "—"}</TableCell>
                      <TableCell className="text-muted-foreground">{fn.ownerEmail ?? "Unassigned"}</TableCell>
                      <TableCell>
                        <Badge variant={fn.isActive ? "default" : "secondary"}>{fn.isActive ? "Active" : "Inactive"}</Badge>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
            {numberTotalPages > 1 && (
              <div className="flex items-center justify-between">
                <p className="text-xs text-muted-foreground">
                  Page {numberPage} of {numberTotalPages} ({numberTotal} total)
                </p>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={() => setNumberPage((p) => Math.max(1, p - 1))} disabled={numberPage <= 1}>
                    Previous
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => setNumberPage((p) => Math.min(numberTotalPages, p + 1))} disabled={numberPage >= numberTotalPages}>
                    Next
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </PageSection>

      <PageSection delay={0.2}>
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
                  <TableHead>Status</TableHead>
                  <TableHead>Received</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {messagesLoading ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-8">
                      <div className="flex items-center justify-center">
                        <div className="h-5 w-5 animate-spin rounded-full border-2 border-muted-foreground border-t-transparent" />
                      </div>
                    </TableCell>
                  </TableRow>
                ) : faxMessages.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground">
                      No recent fax activity.
                    </TableCell>
                  </TableRow>
                ) : (
                  faxMessages.map((msg) => (
                    <TableRow key={msg.id}>
                      <TableCell>
                        <Badge variant={msg.direction === "inbound" ? "outline" : "secondary"}>{msg.direction}</Badge>
                      </TableCell>
                      <TableCell className="font-mono font-medium">{msg.faxNumber}</TableCell>
                      <TableCell className="font-mono text-muted-foreground">{msg.remoteNumber}</TableCell>
                      <TableCell className="text-muted-foreground">{msg.pageCount}</TableCell>
                      <TableCell>
                        <Badge variant={statusVariant[msg.status] ?? "outline"}>{msg.status}</Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground">{new Date(msg.receivedAt).toLocaleString()}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </PageSection>
    </PageContainer>
  )
}
