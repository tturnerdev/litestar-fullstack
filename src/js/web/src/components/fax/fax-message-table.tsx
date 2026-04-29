import { Link } from "@tanstack/react-router"
import { AlertCircle, Printer, Trash2 } from "lucide-react"
import { useState } from "react"
import { DirectionBadge, FaxStatusBadge } from "@/components/fax/fax-status-badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useDeleteFaxMessage, useFaxMessages } from "@/lib/api/hooks/fax"

const PAGE_SIZE = 25

export function FaxMessageTable() {
  const [page, setPage] = useState(1)
  const [direction, setDirection] = useState<string>("")
  const [status, setStatus] = useState<string>("")
  const { data, isLoading, isError } = useFaxMessages({
    page,
    pageSize: PAGE_SIZE,
    direction: direction || undefined,
    status: status || undefined,
  })
  const deleteMutation = useDeleteFaxMessage()

  if (isLoading) {
    return <SkeletonTable rows={6} />
  }

  const hasFilters = !!direction || !!status

  if (isError || !data) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load fax messages"
        description="Something went wrong while fetching your fax messages. Please try refreshing the page."
        action={
          <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
            Refresh page
          </Button>
        }
      />
    )
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE))

  function formatDate(dateStr: string | null): string {
    if (!dateStr) return "—"
    return new Date(dateStr).toLocaleString()
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>Fax Messages</CardTitle>
          <div className="flex gap-2">
            <Select value={direction} onValueChange={(v) => { setDirection(v === "all" ? "" : v); setPage(1) }}>
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Direction" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All directions</SelectItem>
                <SelectItem value="inbound">Inbound</SelectItem>
                <SelectItem value="outbound">Outbound</SelectItem>
              </SelectContent>
            </Select>
            <Select value={status} onValueChange={(v) => { setStatus(v === "all" ? "" : v); setPage(1) }}>
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All statuses</SelectItem>
                <SelectItem value="received">Received</SelectItem>
                <SelectItem value="delivered">Delivered</SelectItem>
                <SelectItem value="sent">Sent</SelectItem>
                <SelectItem value="sending">Sending</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Date</TableHead>
              <TableHead>Direction</TableHead>
              <TableHead>Remote Number</TableHead>
              <TableHead>Pages</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.items.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="p-0">
                  {hasFilters ? (
                    <EmptyState
                      icon={Printer}
                      variant="no-results"
                      title="No results found"
                      description="No fax messages match your current filters. Try adjusting your criteria."
                      action={
                        <Button variant="outline" size="sm" onClick={() => { setDirection(""); setStatus(""); setPage(1) }}>
                          Clear filters
                        </Button>
                      }
                      className="border-0 rounded-none"
                    />
                  ) : (
                    <EmptyState
                      icon={Printer}
                      title="No fax messages yet"
                      description="Fax messages will appear here once you send or receive your first fax."
                      className="border-0 rounded-none"
                    />
                  )}
                </TableCell>
              </TableRow>
            )}
            {data.items.map((msg) => (
              <TableRow key={msg.id}>
                <TableCell className="text-muted-foreground">{formatDate(msg.receivedAt)}</TableCell>
                <TableCell>
                  <DirectionBadge direction={msg.direction} />
                </TableCell>
                <TableCell className="font-mono">{msg.remoteNumber}</TableCell>
                <TableCell>{msg.pageCount}</TableCell>
                <TableCell>
                  <FaxStatusBadge status={msg.status} />
                </TableCell>
                <TableCell className="text-right">
                  <div className="flex justify-end gap-2">
                    <Button asChild variant="outline" size="sm">
                      <Link to="/fax/messages/$messageId" params={{ messageId: msg.id }}>
                        View
                      </Link>
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => deleteMutation.mutate(msg.id)}
                      disabled={deleteMutation.isPending}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
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
