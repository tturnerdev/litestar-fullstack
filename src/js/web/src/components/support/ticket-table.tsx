import { Link } from "@tanstack/react-router"
import { useQueryClient } from "@tanstack/react-query"
import { ArrowDown, ArrowUp, ArrowUpDown, CheckCircle, Download, LifeBuoy, MessageSquare, Search, Trash2, X } from "lucide-react"
import { useCallback, useMemo, useState } from "react"
import { toast } from "sonner"
import { TicketPriorityBadge } from "@/components/support/ticket-priority-badge"
import { TicketStatusBadge } from "@/components/support/ticket-status-badge"
import { BulkActionBar, type BulkAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useTableSelection } from "@/hooks/use-table-selection"
import { type Ticket, type TicketFilters, useTickets } from "@/lib/api/hooks/support"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { client } from "@/lib/generated/api/client.gen"
import { cn } from "@/lib/utils"

const PAGE_SIZE = 25

type SortField = "ticketNumber" | "subject" | "status" | "priority" | "category" | "updatedAt" | "messageCount"
type SortDirection = "asc" | "desc"

const priorityDotColors: Record<string, string> = {
  low: "bg-zinc-400",
  medium: "bg-blue-500",
  high: "bg-amber-500",
  urgent: "bg-red-500",
}

function formatRelativeTime(dateStr: string): string {
  const now = Date.now()
  const date = new Date(dateStr).getTime()
  const diffMs = now - date
  const diffSec = Math.floor(diffMs / 1000)
  const diffMin = Math.floor(diffSec / 60)
  const diffHr = Math.floor(diffMin / 60)
  const diffDay = Math.floor(diffHr / 24)

  if (diffSec < 60) return "just now"
  if (diffMin < 60) return `${diffMin}m ago`
  if (diffHr < 24) return `${diffHr}h ago`
  if (diffDay < 30) return `${diffDay}d ago`
  return new Date(dateStr).toLocaleDateString()
}

function SortableHeader({
  label,
  field,
  currentField,
  currentDirection,
  onSort,
  className,
}: {
  label: string
  field: SortField
  currentField: SortField | null
  currentDirection: SortDirection
  onSort: (field: SortField) => void
  className?: string
}) {
  const isActive = currentField === field
  return (
    <TableHead className={className}>
      <button
        type="button"
        className="flex items-center gap-1 hover:text-foreground transition-colors -ml-1 px-1 py-0.5 rounded"
        onClick={() => onSort(field)}
      >
        {label}
        {isActive ? (
          currentDirection === "asc" ? (
            <ArrowUp className="h-3 w-3" />
          ) : (
            <ArrowDown className="h-3 w-3" />
          )
        ) : (
          <ArrowUpDown className="h-3 w-3 opacity-40" />
        )}
      </button>
    </TableHead>
  )
}

const csvHeaders: CsvHeader<Ticket>[] = [
  { label: "Ticket #", accessor: (t) => t.ticketNumber },
  { label: "Subject", accessor: (t) => t.subject },
  { label: "Status", accessor: (t) => t.status },
  { label: "Priority", accessor: (t) => t.priority },
  { label: "Category", accessor: (t) => t.category ?? "" },
  { label: "Created", accessor: (t) => t.createdAt ?? "" },
  { label: "Updated", accessor: (t) => t.updatedAt ?? "" },
]

const getId = (t: Ticket) => t.id

export function TicketTable() {
  const [page, setPage] = useState(1)
  const [filters, setFilters] = useState<TicketFilters>({})
  const [searchInput, setSearchInput] = useState("")
  const [sortField, setSortField] = useState<SortField | null>(null)
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc")
  const { data, isLoading, isError } = useTickets(page, PAGE_SIZE, filters)
  const queryClient = useQueryClient()

  const handleSort = useCallback((field: SortField) => {
    setSortField((prev) => {
      if (prev === field) {
        setSortDirection((d) => (d === "asc" ? "desc" : "asc"))
        return field
      }
      setSortDirection("desc")
      return field
    })
  }, [])

  const priorityOrder: Record<string, number> = useMemo(() => ({ low: 0, medium: 1, high: 2, urgent: 3 }), [])

  const items: Ticket[] = useMemo(() => {
    const raw = data?.items ?? []
    if (!sortField) return raw
    const sorted = [...raw].sort((a, b) => {
      let cmp = 0
      switch (sortField) {
        case "ticketNumber":
          cmp = (a.ticketNumber ?? "").localeCompare(b.ticketNumber ?? "")
          break
        case "subject":
          cmp = a.subject.localeCompare(b.subject)
          break
        case "status":
          cmp = a.status.localeCompare(b.status)
          break
        case "priority":
          cmp = (priorityOrder[a.priority] ?? 0) - (priorityOrder[b.priority] ?? 0)
          break
        case "category":
          cmp = (a.category ?? "").localeCompare(b.category ?? "")
          break
        case "messageCount":
          cmp = a.messageCount - b.messageCount
          break
        case "updatedAt": {
          const aTime = new Date(a.updatedAt ?? a.createdAt ?? 0).getTime()
          const bTime = new Date(b.updatedAt ?? b.createdAt ?? 0).getTime()
          cmp = aTime - bTime
          break
        }
      }
      return sortDirection === "asc" ? cmp : -cmp
    })
    return sorted
  }, [data, sortField, sortDirection, priorityOrder])
  const selection = useTableSelection(items, getId)

  const updateFilter = useCallback(
    (key: keyof TicketFilters, value: string) => {
      setPage(1)
      setFilters((prev) => ({ ...prev, [key]: value || undefined }))
    },
    [],
  )

  const handleSearch = useCallback(() => {
    setPage(1)
    setFilters((prev) => ({ ...prev, search: searchInput || undefined }))
  }, [searchInput])

  const clearFilters = useCallback(() => {
    setPage(1)
    setFilters({})
    setSearchInput("")
  }, [])

  const hasFilters =
    !!filters.status || !!filters.priority || !!filters.category || !!filters.search

  const handleExportAll = useCallback(() => {
    if (!items.length) return
    exportToCsv("tickets", csvHeaders, items)
  }, [items])

  const handleSelectAllToggle = useCallback(() => {
    if (selection.allSelected) {
      selection.deselectAll()
    } else {
      selection.selectAll()
    }
  }, [selection])

  const bulkActions: BulkAction[] = useMemo(() => [
    {
      key: "close",
      label: "Close Selected",
      icon: <CheckCircle className="h-4 w-4" />,
      variant: "outline",
      confirm: {
        title: "Close selected tickets?",
        description: "The selected tickets will be marked as closed. You can reopen them later.",
      },
      onExecute: async (ids) => {
        const errors: string[] = []
        for (const id of ids) {
          try {
            await client.post({
              url: `/api/support/tickets/${id}/close`,
              security: [{ scheme: "bearer", type: "http" }],
            } as never)
          } catch {
            errors.push(id)
          }
        }
        queryClient.invalidateQueries({ queryKey: ["support", "tickets"] })
        if (errors.length > 0) {
          toast.error(`Failed to close ${errors.length} of ${ids.length} tickets`)
        } else {
          toast.success(`Closed ${ids.length} ticket${ids.length === 1 ? "" : "s"}`)
        }
      },
    },
    {
      key: "delete",
      label: "Delete Selected",
      icon: <Trash2 className="h-4 w-4" />,
      variant: "destructive",
      confirm: {
        title: "Delete selected tickets?",
        description: "This action cannot be undone. All selected tickets and their messages will be permanently deleted.",
      },
      onExecute: async (ids) => {
        const errors: string[] = []
        for (const id of ids) {
          try {
            await client.delete({
              url: `/api/support/tickets/${id}`,
              security: [{ scheme: "bearer", type: "http" }],
            } as never)
          } catch {
            errors.push(id)
          }
        }
        queryClient.invalidateQueries({ queryKey: ["support", "tickets"] })
        if (errors.length > 0) {
          toast.error(`Failed to delete ${errors.length} of ${ids.length} tickets`)
        } else {
          toast.success(`Deleted ${ids.length} ticket${ids.length === 1 ? "" : "s"}`)
        }
      },
    },
    {
      key: "export",
      label: "Export Selected",
      icon: <Download className="h-4 w-4" />,
      variant: "outline",
      onExecute: async (ids) => {
        const selected = items.filter((t) => ids.includes(t.id))
        exportToCsv("tickets-selected", csvHeaders, selected)
        toast.success(`Exported ${selected.length} ticket${selected.length === 1 ? "" : "s"}`)
      },
    },
  ], [items, queryClient])

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Tickets</CardTitle>
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={items.length === 0}>
              <Download className="mr-1 h-3.5 w-3.5" />
              Export All
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search tickets..."
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") handleSearch()
                  }}
                  className="h-8 w-[220px] pl-8 text-sm"
                />
              </div>
              <Button
                variant="outline"
                size="sm"
                className="h-8"
                onClick={handleSearch}
              >
                Search
              </Button>
            </div>
            <Select
              value={filters.status ?? "all"}
              onValueChange={(v) => updateFilter("status", v === "all" ? "" : v)}
            >
              <SelectTrigger className="h-8 w-[140px] text-sm">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="open">Open</SelectItem>
                <SelectItem value="in_progress">In Progress</SelectItem>
                <SelectItem value="waiting_on_customer">Waiting (Customer)</SelectItem>
                <SelectItem value="waiting_on_support">Waiting (Support)</SelectItem>
                <SelectItem value="resolved">Resolved</SelectItem>
                <SelectItem value="closed">Closed</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={filters.priority ?? "all"}
              onValueChange={(v) => updateFilter("priority", v === "all" ? "" : v)}
            >
              <SelectTrigger className="h-8 w-[130px] text-sm">
                <SelectValue placeholder="Priority" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Priorities</SelectItem>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="urgent">Urgent</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={filters.category ?? "all"}
              onValueChange={(v) => updateFilter("category", v === "all" ? "" : v)}
            >
              <SelectTrigger className="h-8 w-[130px] text-sm">
                <SelectValue placeholder="Category" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Categories</SelectItem>
                <SelectItem value="general">General</SelectItem>
                <SelectItem value="billing">Billing</SelectItem>
                <SelectItem value="technical">Technical</SelectItem>
                <SelectItem value="account">Account</SelectItem>
                <SelectItem value="device">Device</SelectItem>
                <SelectItem value="voice">Voice</SelectItem>
                <SelectItem value="fax">Fax</SelectItem>
              </SelectContent>
            </Select>
            {hasFilters && (
              <Button
                variant="ghost"
                size="sm"
                className="h-8 text-xs"
                onClick={clearFilters}
              >
                <X className="mr-1 h-3 w-3" />
                Clear
              </Button>
            )}
          </div>

          {isLoading ? (
            <SkeletonTable rows={6} />
          ) : isError || !data ? (
            <div className="text-center text-muted-foreground py-8">
              We could not load tickets.
            </div>
          ) : data.items.length === 0 && page === 1 && !hasFilters ? (
            <div className="py-16 text-center space-y-6">
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
            </div>
          ) : data.items.length === 0 ? (
            <div className="py-16 text-center space-y-4">
              <div className="mx-auto w-12 h-12 rounded-full bg-muted flex items-center justify-center">
                <LifeBuoy className="h-6 w-6 text-muted-foreground" />
              </div>
              <div className="space-y-1">
                <p className="text-sm font-medium">No tickets match your filters</p>
                <p className="text-xs text-muted-foreground">Try adjusting your search or filter criteria.</p>
              </div>
              <Button variant="outline" size="sm" onClick={clearFilters}>
                <X className="mr-1 h-3 w-3" />
                Clear filters
              </Button>
            </div>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={selection.allSelected}
                        indeterminate={selection.someSelected}
                        onChange={handleSelectAllToggle}
                        aria-label="Select all tickets"
                      />
                    </TableHead>
                    <SortableHeader label="Ticket" field="ticketNumber" currentField={sortField} currentDirection={sortDirection} onSort={handleSort} className="w-[100px]" />
                    <SortableHeader label="Subject" field="subject" currentField={sortField} currentDirection={sortDirection} onSort={handleSort} />
                    <SortableHeader label="Status" field="status" currentField={sortField} currentDirection={sortDirection} onSort={handleSort} />
                    <SortableHeader label="Priority" field="priority" currentField={sortField} currentDirection={sortDirection} onSort={handleSort} />
                    <SortableHeader label="Category" field="category" currentField={sortField} currentDirection={sortDirection} onSort={handleSort} />
                    <SortableHeader label="Messages" field="messageCount" currentField={sortField} currentDirection={sortDirection} onSort={handleSort} />
                    <SortableHeader label="Updated" field="updatedAt" currentField={sortField} currentDirection={sortDirection} onSort={handleSort} />
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((ticket) => {
                    const displayDate = ticket.updatedAt ?? ticket.createdAt
                    const dotColor = priorityDotColors[ticket.priority] ?? "bg-zinc-400"
                    return (
                      <TableRow
                        key={ticket.id}
                        className={cn(
                          "transition-colors duration-150 hover:bg-muted/50",
                          !ticket.isReadByUser && "bg-primary/[0.02]",
                        )}
                        data-state={selection.isSelected(ticket.id) ? "selected" : undefined}
                      >
                        <TableCell>
                          <Checkbox
                            checked={selection.isSelected(ticket.id)}
                            onChange={() => selection.toggle(ticket.id)}
                            aria-label={`Select ticket ${ticket.ticketNumber}`}
                          />
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          <div className="flex items-center gap-1.5">
                            {!ticket.isReadByUser && (
                              <span className="h-1.5 w-1.5 rounded-full bg-primary" />
                            )}
                            {ticket.ticketNumber}
                          </div>
                        </TableCell>
                        <TableCell>
                          <Link
                            to="/support/$ticketId"
                            params={{ ticketId: ticket.id }}
                            className={cn(
                              "hover:underline",
                              ticket.isReadByUser ? "font-medium" : "font-semibold",
                            )}
                          >
                            {ticket.subject}
                          </Link>
                          {ticket.latestMessagePreview && (
                            <p className="text-xs text-muted-foreground line-clamp-1 mt-0.5">
                              {ticket.latestMessagePreview}
                            </p>
                          )}
                        </TableCell>
                        <TableCell>
                          <TicketStatusBadge status={ticket.status} />
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <span className={cn("h-2 w-2 rounded-full shrink-0", dotColor)} />
                            <TicketPriorityBadge priority={ticket.priority} />
                          </div>
                        </TableCell>
                        <TableCell className="text-sm capitalize text-muted-foreground">
                          {ticket.category ?? "—"}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1.5 text-muted-foreground">
                            <MessageSquare className="h-3.5 w-3.5" />
                            <span className="text-sm">{ticket.messageCount}</span>
                          </div>
                        </TableCell>
                        <TableCell className="text-muted-foreground text-sm">
                          {displayDate ? (
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <span className="cursor-default">{formatRelativeTime(displayDate)}</span>
                              </TooltipTrigger>
                              <TooltipContent>
                                {new Date(displayDate).toLocaleString()}
                              </TooltipContent>
                            </Tooltip>
                          ) : (
                            "—"
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button asChild variant="outline" size="sm">
                            <Link to="/support/$ticketId" params={{ ticketId: ticket.id }}>
                              View
                            </Link>
                          </Button>
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
              {Math.ceil(data.total / PAGE_SIZE) > 1 && (
                <div className="flex items-center justify-between">
                  <p className="text-xs text-muted-foreground">
                    Page {page} of {Math.ceil(data.total / PAGE_SIZE)} ({data.total} tickets)
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
                      onClick={() =>
                        setPage((p) => Math.min(Math.ceil(data.total / PAGE_SIZE), p + 1))
                      }
                      disabled={page >= Math.ceil(data.total / PAGE_SIZE)}
                    >
                      Next
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      <BulkActionBar
        selectedCount={selection.selectedCount}
        selectedIds={[...selection.selectedIds]}
        onClearSelection={selection.deselectAll}
        actions={bulkActions}
      />
    </>
  )
}
