import { Link } from "@tanstack/react-router"
import { AlertCircle, Check, Copy, Printer, RefreshCw, Trash2, X } from "lucide-react"
import { useState } from "react"
import { DirectionBadge, FaxStatusBadge } from "@/components/fax/fax-status-badge"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDeleteFaxMessage, useFaxMessages } from "@/lib/api/hooks/fax"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"

const PAGE_SIZE = 25

function formatUSPhone(phone: string): string {
  const cleaned = phone.replace(/\D/g, "")
  if (cleaned.length === 11 && cleaned.startsWith("1")) {
    const area = cleaned.slice(1, 4)
    const prefix = cleaned.slice(4, 7)
    const line = cleaned.slice(7)
    return `(${area}) ${prefix}-${line}`
  }
  return phone
}

export function FaxMessageTable() {
  const [page, setPage] = useState(1)
  const [direction, setDirection] = useState<string>("")
  const [status, setStatus] = useState<string>("")
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; remoteNumber: string } | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const { data, isLoading, isError, isFetching, refetch } = useFaxMessages({
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
  const activeFilterCount = (direction ? 1 : 0) + (status ? 1 : 0)

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
  const showingStart = (page - 1) * PAGE_SIZE + 1
  const showingEnd = Math.min(page * PAGE_SIZE, data.total)

  function clearFilters() {
    setDirection("")
    setStatus("")
    setPage(1)
  }

  function handleCopy(id: string, value: string) {
    void navigator.clipboard.writeText(value).then(() => {
      setCopiedId(id)
      setTimeout(() => setCopiedId(null), 2000)
    })
  }

  function handleDeleteConfirm() {
    if (deleteTarget) {
      deleteMutation.mutate(deleteTarget.id)
      setDeleteTarget(null)
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CardTitle>Fax Messages</CardTitle>
              {data.total > 0 && (
                <span className="text-sm font-normal text-muted-foreground">({data.total})</span>
              )}
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="icon"
                className="h-9 w-9"
                onClick={() => refetch()}
                disabled={isFetching}
                aria-label="Refresh fax messages"
              >
                <RefreshCw className={`h-4 w-4 ${isFetching ? "animate-spin" : ""}`} />
              </Button>
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
              {hasFilters && (
                <>
                  <Badge variant="secondary" className="tabular-nums">
                    {activeFilterCount} active
                  </Badge>
                  <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={clearFilters}>
                    <X className="mr-1 h-3 w-3" />
                    Clear all
                  </Button>
                </>
              )}
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
                          <Button variant="outline" size="sm" onClick={clearFilters}>
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
              {data.items.map((msg, index) => (
                <TableRow key={msg.id} className={`hover:bg-muted/50 ${index % 2 === 1 ? "bg-muted/20" : ""}`}>
                  <TableCell className="text-muted-foreground">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="cursor-default">{formatRelativeTimeShort(msg.receivedAt)}</span>
                      </TooltipTrigger>
                      <TooltipContent>{formatDateTime(msg.receivedAt)}</TooltipContent>
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    <DirectionBadge direction={msg.direction} />
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <span className="font-mono">{formatUSPhone(msg.remoteNumber)}</span>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-6 w-6"
                        onClick={() => handleCopy(msg.id, msg.remoteNumber)}
                        aria-label="Copy phone number"
                      >
                        {copiedId === msg.id ? (
                          <Check className="h-3 w-3 text-green-500" />
                        ) : (
                          <Copy className="h-3 w-3 text-muted-foreground" />
                        )}
                      </Button>
                    </div>
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
                        onClick={() => setDeleteTarget({ id: msg.id, remoteNumber: msg.remoteNumber })}
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
          {data.total > 0 && (
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">
                Showing {showingStart}–{showingEnd} of {data.total} messages
              </p>
              {totalPages > 1 && (
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>
                    Previous
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>
                    Next
                  </Button>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <AlertDialog open={deleteTarget !== null} onOpenChange={(open) => { if (!open) setDeleteTarget(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete fax message?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete the fax message {deleteTarget ? `to/from ${formatUSPhone(deleteTarget.remoteNumber)}` : ""}. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setDeleteTarget(null)}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={handleDeleteConfirm}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
