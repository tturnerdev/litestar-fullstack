import { useQueryClient } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { AlertTriangle, FileText, Loader2, RefreshCw, Search, Trash2 } from "lucide-react"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { DirectionBadge, FaxStatusBadge } from "@/components/fax/fax-status-badge"
import { Badge } from "@/components/ui/badge"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
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
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDeleteFaxMessage, useFaxMessages, useFaxNumbers } from "@/lib/api/hooks/fax"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"

const PAGE_SIZE = 25

function useDebounce<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(timer)
  }, [value, delayMs])
  return debounced
}

export function FaxMessageList() {
  const [page, setPage] = useState(1)
  const [direction, setDirection] = useState<string>("")
  const [status, setStatus] = useState<string>("")
  const [searchInput, setSearchInput] = useState("")
  const debouncedSearch = useDebounce(searchInput, 300)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false)
  const queryClient = useQueryClient()
  const searchRef = useRef<HTMLInputElement>(null)

  const { data: faxNumbers } = useFaxNumbers(1, 100)
  const { data, isLoading, isError, isFetching } = useFaxMessages({
    page,
    pageSize: PAGE_SIZE,
    direction: direction || undefined,
    status: status || undefined,
    search: debouncedSearch || undefined,
  })
  const deleteMutation = useDeleteFaxMessage()

  // Reset selection when data changes
  useEffect(() => {
    setSelectedIds(new Set())
  }, [page, direction, status, debouncedSearch])

  const allOnPageSelected = useMemo(() => {
    if (!data?.items.length) return false
    return data.items.every((msg) => selectedIds.has(msg.id))
  }, [data?.items, selectedIds])

  const someOnPageSelected = useMemo(() => {
    if (!data?.items.length) return false
    return data.items.some((msg) => selectedIds.has(msg.id)) && !allOnPageSelected
  }, [data?.items, selectedIds, allOnPageSelected])

  const toggleSelectAll = useCallback(() => {
    if (!data?.items) return
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (allOnPageSelected) {
        for (const msg of data.items) next.delete(msg.id)
      } else {
        for (const msg of data.items) next.add(msg.id)
      }
      return next
    })
  }, [data?.items, allOnPageSelected])

  const toggleSelect = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  function handleConfirmDelete() {
    if (!deleteTarget) return
    deleteMutation.mutate(deleteTarget, {
      onSuccess: () => setDeleteTarget(null),
    })
  }

  function handleBulkDelete() {
    const ids = Array.from(selectedIds)
    let completed = 0
    for (const id of ids) {
      deleteMutation.mutate(id, {
        onSuccess: () => {
          completed++
          if (completed === ids.length) {
            setSelectedIds(new Set())
            setBulkDeleteOpen(false)
          }
        },
      })
    }
  }

  function handleRefresh() {
    queryClient.invalidateQueries({ queryKey: ["fax", "messages"] })
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
  const startItem = (page - 1) * PAGE_SIZE + 1
  const endItem = Math.min(page * PAGE_SIZE, data.total)

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <CardTitle>Fax Messages</CardTitle>
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  ref={searchRef}
                  placeholder="Search remote number..."
                  value={searchInput}
                  onChange={(e) => {
                    setSearchInput(e.target.value)
                    setPage(1)
                  }}
                  className="w-[200px] pl-9"
                />
              </div>
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
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={handleRefresh}
                    disabled={isFetching}
                    className="shrink-0"
                  >
                    <RefreshCw className={`h-4 w-4 ${isFetching ? "animate-spin" : ""}`} />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Refresh</TooltipContent>
              </Tooltip>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {selectedIds.size > 0 && (
            <div className="flex items-center gap-3 rounded-md border border-destructive/20 bg-destructive/5 px-4 py-2">
              <span className="text-sm font-medium">
                {selectedIds.size} message{selectedIds.size !== 1 ? "s" : ""} selected
              </span>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => setBulkDeleteOpen(true)}
              >
                <Trash2 className="mr-2 h-3.5 w-3.5" />
                Delete selected
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSelectedIds(new Set())}
              >
                Clear selection
              </Button>
            </div>
          )}
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[40px]">
                  <Checkbox
                    checked={allOnPageSelected}
                    indeterminate={someOnPageSelected}
                    onChange={toggleSelectAll}
                    aria-label="Select all messages on this page"
                  />
                </TableHead>
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
                  <TableCell colSpan={8} className="text-center text-muted-foreground">
                    <div className="flex flex-col items-center gap-2 py-8">
                      <FileText className="h-8 w-8 text-muted-foreground/50" />
                      <p>No fax messages found.</p>
                      {(direction || status || searchInput) && (
                        <Button
                          variant="link"
                          size="sm"
                          onClick={() => {
                            setDirection("")
                            setStatus("")
                            setSearchInput("")
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
                <TableRow
                  key={msg.id}
                  className="group transition-colors hover:bg-muted/50"
                >
                  <TableCell>
                    <Checkbox
                      checked={selectedIds.has(msg.id)}
                      onChange={() => toggleSelect(msg.id)}
                      aria-label={`Select message from ${msg.remoteNumber}`}
                    />
                  </TableCell>
                  <TableCell className="text-muted-foreground whitespace-nowrap">
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
                  <TableCell className="font-mono">{msg.remoteNumber}</TableCell>
                  <TableCell className="text-muted-foreground text-sm">
                    {getFaxNumberLabel(msg.faxNumberId)}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1.5">
                      <FileText className="h-3.5 w-3.5 text-muted-foreground" />
                      <Badge variant="secondary" className="text-xs tabular-nums">
                        {msg.pageCount}
                      </Badge>
                    </div>
                  </TableCell>
                  <TableCell>
                    {msg.status === "failed" && msg.errorMessage ? (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span><FaxStatusBadge status={msg.status} /></span>
                        </TooltipTrigger>
                        <TooltipContent className="max-w-xs">{msg.errorMessage}</TooltipContent>
                      </Tooltip>
                    ) : (
                      <FaxStatusBadge status={msg.status} />
                    )}
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
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              {data.total > 0
                ? `Showing ${startItem}-${endItem} of ${data.total} messages`
                : "No messages"}
            </p>
            {totalPages > 1 && (
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
            )}
          </div>
        </CardContent>
      </Card>

      {/* Single delete dialog */}
      <AlertDialog open={deleteTarget !== null} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete Fax Message
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will <strong>permanently delete</strong> this fax message and its associated
              document. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setDeleteTarget(null)}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              className={buttonVariants({ variant: "destructive" })}
              onClick={handleConfirmDelete}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {deleteMutation.isPending ? "Deleting..." : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Bulk delete dialog */}
      <AlertDialog open={bulkDeleteOpen} onOpenChange={(open) => !open && setBulkDeleteOpen(false)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete {selectedIds.size} Fax Message{selectedIds.size !== 1 ? "s" : ""}
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will <strong>permanently delete {selectedIds.size}</strong> fax
              message{selectedIds.size !== 1 ? "s" : ""} and their associated documents.
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setBulkDeleteOpen(false)}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              className={buttonVariants({ variant: "destructive" })}
              onClick={handleBulkDelete}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {deleteMutation.isPending ? "Deleting..." : `Delete ${selectedIds.size} message${selectedIds.size !== 1 ? "s" : ""}`}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
