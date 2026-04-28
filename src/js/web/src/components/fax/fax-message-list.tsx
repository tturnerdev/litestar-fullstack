import { Link } from "@tanstack/react-router"
import { FileText, Trash2 } from "lucide-react"
import { useState } from "react"
import { DirectionBadge, FaxStatusBadge } from "@/components/fax/fax-status-badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useDeleteFaxMessage, useFaxMessages, useFaxNumbers } from "@/lib/api/hooks/fax"

const PAGE_SIZE = 25

function formatDate(dateStr: string | null): string {
  if (!dateStr) return "--"
  return new Date(dateStr).toLocaleString()
}

export function FaxMessageList() {
  const [page, setPage] = useState(1)
  const [direction, setDirection] = useState<string>("")
  const [status, setStatus] = useState<string>("")
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)

  const { data: faxNumbers } = useFaxNumbers(1, 100)
  const { data, isLoading, isError } = useFaxMessages({
    page,
    pageSize: PAGE_SIZE,
    direction: direction || undefined,
    status: status || undefined,
  })
  const deleteMutation = useDeleteFaxMessage()

  function handleConfirmDelete() {
    if (!deleteTarget) return
    deleteMutation.mutate(deleteTarget, {
      onSuccess: () => setDeleteTarget(null),
    })
  }

  function getFaxNumberLabel(faxNumberId: string): string {
    const num = faxNumbers?.items.find((n) => n.id === faxNumberId)
    if (!num) return ""
    return num.label ?? num.number
  }

  if (isLoading) {
    return <SkeletonTable rows={6} />
  }

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Fax Messages</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">We could not load fax messages.</CardContent>
      </Card>
    )
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE))

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <CardTitle>Fax Messages</CardTitle>
            <div className="flex flex-wrap gap-2">
              <Select
                value={direction}
                onValueChange={(v) => {
                  setDirection(v === "all" ? "" : v)
                  setPage(1)
                }}
              >
                <SelectTrigger className="w-[140px]">
                  <SelectValue placeholder="Direction" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All directions</SelectItem>
                  <SelectItem value="inbound">Inbound</SelectItem>
                  <SelectItem value="outbound">Outbound</SelectItem>
                </SelectContent>
              </Select>
              <Select
                value={status}
                onValueChange={(v) => {
                  setStatus(v === "all" ? "" : v)
                  setPage(1)
                }}
              >
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
                <TableHead>Fax Line</TableHead>
                <TableHead>Pages</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground">
                    <div className="flex flex-col items-center gap-2 py-8">
                      <FileText className="h-8 w-8 text-muted-foreground/50" />
                      <p>No fax messages found.</p>
                      {(direction || status) && (
                        <Button
                          variant="link"
                          size="sm"
                          onClick={() => {
                            setDirection("")
                            setStatus("")
                            setPage(1)
                          }}
                        >
                          Clear filters
                        </Button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              )}
              {data.items.map((msg) => (
                <TableRow key={msg.id} className="group">
                  <TableCell className="text-muted-foreground whitespace-nowrap">
                    {formatDate(msg.receivedAt)}
                  </TableCell>
                  <TableCell>
                    <DirectionBadge direction={msg.direction} />
                  </TableCell>
                  <TableCell className="font-mono">{msg.remoteNumber}</TableCell>
                  <TableCell className="text-muted-foreground text-sm">
                    {getFaxNumberLabel(msg.faxNumberId)}
                  </TableCell>
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
                        onClick={() => setDeleteTarget(msg.id)}
                        className="text-destructive hover:text-destructive hover:bg-destructive/10"
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
                Page {page} of {totalPages} ({data.total} total)
              </p>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page <= 1}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={deleteTarget !== null} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Fax Message</DialogTitle>
            <DialogDescription>
              This will permanently delete this fax message and its associated document. This
              action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleConfirmDelete}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
