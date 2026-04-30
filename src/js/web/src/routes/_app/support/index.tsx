import { createFileRoute, Link } from "@tanstack/react-router"
import { useQueryClient } from "@tanstack/react-query"
import { useCallback, useMemo, useState } from "react"
import {
  AlertCircle,
  CheckCircle,
  Download,
  Home,
  LifeBuoy,
  Plus,
  Search,
  Trash2,
  X,
} from "lucide-react"
import { toast } from "sonner"
import { TicketPriorityBadge } from "@/components/support/ticket-priority-badge"
import { TicketStatusBadge } from "@/components/support/ticket-status-badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Badge } from "@/components/ui/badge"
import { BulkActionBar, type BulkAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { DateRangeFilter, getPresetDates, isDateInRange } from "@/components/ui/date-range-filter"
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { type Ticket, useTickets } from "@/lib/api/hooks/support"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { client } from "@/lib/generated/api/client.gen"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/support/")({
  component: SupportPage,
})

// ── Constants ────────────────────────────────────────────────────────────

const PAGE_SIZE = 25

const statusOptions: FilterOption[] = [
  { value: "open", label: "Open" },
  { value: "in_progress", label: "In Progress" },
  { value: "waiting_on_customer", label: "Waiting (Customer)" },
  { value: "waiting_on_support", label: "Waiting (Support)" },
  { value: "resolved", label: "Resolved" },
  { value: "closed", label: "Closed" },
]

const priorityOptions: FilterOption[] = [
  { value: "low", label: "Low" },
  { value: "medium", label: "Medium" },
  { value: "high", label: "High" },
  { value: "urgent", label: "Urgent" },
]

const categoryOptions: FilterOption[] = [
  { value: "general", label: "General" },
  { value: "billing", label: "Billing" },
  { value: "technical", label: "Technical" },
  { value: "account", label: "Account" },
  { value: "device", label: "Device" },
  { value: "voice", label: "Voice" },
  { value: "fax", label: "Fax" },
]

const csvHeaders: CsvHeader<Ticket>[] = [
  { label: "Ticket #", accessor: (t) => t.ticketNumber },
  { label: "Subject", accessor: (t) => t.subject },
  { label: "Status", accessor: (t) => t.status },
  { label: "Priority", accessor: (t) => t.priority },
  { label: "Category", accessor: (t) => t.category ?? "" },
  { label: "Created", accessor: (t) => t.createdAt ?? "" },
  { label: "Updated", accessor: (t) => t.updatedAt ?? "" },
]

// ── Helpers ──────────────────────────────────────────────────────────────

// ── Main page ────────────────────────────────────────────────────────────

function SupportPage() {
  // Filter & search state
  const [search, setSearch] = useState("")
  const [statusFilter, setStatusFilter] = useState<string[]>([])
  const [priorityFilter, setPriorityFilter] = useState<string[]>([])
  const [categoryFilter, setCategoryFilter] = useState<string[]>([])
  const [startDate, setStartDate] = useState("")
  const [endDate, setEndDate] = useState("")
  const [page, setPage] = useState(1)

  // Sort state
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  const queryClient = useQueryClient()

  // Build server-side filters (status/priority/category are single-value on backend,
  // so when multiple are selected we rely on client-side filtering)
  const serverFilters = useMemo(() => {
    return {
      search: search || undefined,
      status: statusFilter.length === 1 ? statusFilter[0] : undefined,
      priority: priorityFilter.length === 1 ? priorityFilter[0] : undefined,
      category: categoryFilter.length === 1 ? categoryFilter[0] : undefined,
      orderBy: sortKey ?? undefined,
      sortOrder: sortDir ?? undefined,
    }
  }, [search, statusFilter, priorityFilter, categoryFilter, sortKey, sortDir])

  const { data, isLoading, isError, refetch } = useTickets(page, PAGE_SIZE, serverFilters)

  // Apply client-side multi-value filters
  const filteredItems = useMemo(() => {
    if (!data?.items) return []
    return data.items.filter((ticket) => {
      if (statusFilter.length > 1 && !statusFilter.includes(ticket.status)) return false
      if (priorityFilter.length > 1 && !priorityFilter.includes(ticket.priority)) return false
      if (categoryFilter.length > 1 && ticket.category && !categoryFilter.includes(ticket.category))
        return false
      if ((startDate || endDate) && !isDateInRange(ticket.createdAt, startDate, endDate))
        return false
      return true
    })
  }, [data?.items, statusFilter, priorityFilter, categoryFilter, startDate, endDate])

  // Selection helpers
  const allVisibleIds = useMemo(() => filteredItems.map((t) => t.id), [filteredItems])
  const allSelected = filteredItems.length > 0 && filteredItems.every((t) => selectedIds.has(t.id))
  const someSelected = filteredItems.some((t) => selectedIds.has(t.id))

  const toggleAll = useCallback(() => {
    if (allSelected) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(allVisibleIds))
    }
  }, [allSelected, allVisibleIds])

  const toggleOne = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }, [])

  // Sort handler
  const handleSort = useCallback(
    (key: string) => {
      const next = nextSortDirection(sortKey, sortDir, key)
      setSortKey(next.sort)
      setSortDir(next.direction)
      setPage(1)
    },
    [sortKey, sortDir],
  )

  // Date range handler
  const handleDatePreset = useCallback(
    (days: number) => {
      const { start, end } = getPresetDates(days)
      setStartDate(start)
      setEndDate(end)
      setPage(1)
    },
    [],
  )

  // Filter helpers
  const activeFilterCount =
    statusFilter.length + priorityFilter.length + categoryFilter.length + (startDate || endDate ? 1 : 0)
  const hasAnyFilters = activeFilterCount > 0 || !!search

  const clearAllFilters = useCallback(() => {
    setSearch("")
    setStatusFilter([])
    setPriorityFilter([])
    setCategoryFilter([])
    setStartDate("")
    setEndDate("")
    setPage(1)
  }, [])

  const handleSearchChange = useCallback(
    (value: string) => {
      setSearch(value)
      setPage(1)
    },
    [],
  )

  // Export
  const handleExportAll = useCallback(() => {
    if (!filteredItems.length) return
    exportToCsv("tickets", csvHeaders, filteredItems)
    toast.success(`Exported ${filteredItems.length} ticket${filteredItems.length === 1 ? "" : "s"}`)
  }, [filteredItems])

  // Bulk actions
  const bulkActions: BulkAction[] = useMemo(
    () => [
      {
        key: "close",
        label: "Close Selected",
        icon: <CheckCircle className="h-4 w-4" />,
        variant: "outline",
        confirm: {
          title: "Close selected tickets?",
          description:
            "The selected tickets will be marked as closed. You can reopen them later.",
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
          setSelectedIds(new Set())
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
          description:
            "This action cannot be undone. All selected tickets and their messages will be permanently deleted.",
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
          setSelectedIds(new Set())
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
          const selected = filteredItems.filter((t) => ids.includes(t.id))
          exportToCsv("tickets-selected", csvHeaders, selected)
          toast.success(
            `Exported ${selected.length} ticket${selected.length === 1 ? "" : "s"}`,
          )
        },
      },
    ],
    [filteredItems, queryClient],
  )

  const hasData = filteredItems.length > 0
  const hasAnyTickets = (data?.items.length ?? 0) > 0
  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0

  const breadcrumbs = (
    <Breadcrumb>
      <BreadcrumbList>
        <BreadcrumbItem>
          <BreadcrumbLink asChild>
            <Link to="/">
              <Home className="h-3.5 w-3.5" />
            </Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          <BreadcrumbPage>Support</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Helpdesk"
        title="Tickets"
        description="View and manage support tickets."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!hasData}>
              <Download className="mr-1.5 h-3.5 w-3.5" />
              Export
            </Button>
            <Button size="sm" asChild>
              <Link to="/support/new">
                <Plus className="mr-2 h-4 w-4" /> New Ticket
              </Link>
            </Button>
          </div>
        }
      />

      {/* Search & filters */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search by subject or description..."
              value={search}
              onChange={(e) => handleSearchChange(e.target.value)}
              className="pl-9 pr-8"
            />
            {search && (
              <button
                type="button"
                onClick={() => handleSearchChange("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
              >
                <X className="h-3.5 w-3.5" />
                <span className="sr-only">Clear search</span>
              </button>
            )}
          </div>
          <FilterDropdown
            label="Status"
            options={statusOptions}
            selected={statusFilter}
            onChange={(v) => {
              setStatusFilter(v)
              setPage(1)
            }}
          />
          <FilterDropdown
            label="Priority"
            options={priorityOptions}
            selected={priorityFilter}
            onChange={(v) => {
              setPriorityFilter(v)
              setPage(1)
            }}
          />
          <FilterDropdown
            label="Category"
            options={categoryOptions}
            selected={categoryFilter}
            onChange={(v) => {
              setCategoryFilter(v)
              setPage(1)
            }}
          />
          <DateRangeFilter
            startDate={startDate}
            endDate={endDate}
            onStartDateChange={(v) => {
              setStartDate(v)
              setPage(1)
            }}
            onEndDateChange={(v) => {
              setEndDate(v)
              setPage(1)
            }}
            onPreset={handleDatePreset}
            label="Created"
          />
          {hasAnyFilters && (
            <Button
              variant="ghost"
              size="sm"
              className="text-xs text-muted-foreground"
              onClick={clearAllFilters}
            >
              Clear all filters
            </Button>
          )}
        </div>
      </PageSection>

      {/* Content */}
      <PageSection delay={0.1}>
        {isLoading ? (
          <SkeletonTable rows={6} />
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load tickets"
            description="Something went wrong while fetching your tickets. Please try again."
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Try again
              </Button>
            }
          />
        ) : !hasAnyTickets && !hasAnyFilters ? (
          <EmptyState
            icon={LifeBuoy}
            title="No tickets yet"
            description="Create your first support ticket to get help from our team. We're here to assist you with any questions or issues."
            action={
              <Button size="sm" asChild>
                <Link to="/support/new">
                  <Plus className="mr-2 h-4 w-4" /> Create your first ticket
                </Link>
              </Button>
            }
          />
        ) : !hasData ? (
          <EmptyState
            icon={LifeBuoy}
            variant="no-results"
            title="No results found"
            description="No tickets match your current filters. Try adjusting your search or filters."
            action={
              <Button variant="outline" size="sm" onClick={clearAllFilters}>
                Clear all filters
              </Button>
            }
          />
        ) : (
          <div className="space-y-3">
            {/* Result count & pagination info */}
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                {data ? data.total : filteredItems.length} ticket
                {(data?.total ?? filteredItems.length) === 1 ? "" : "s"}
                {activeFilterCount > 0 && " (filtered)"}
              </p>
              {totalPages > 1 && (
                <p className="text-xs text-muted-foreground">
                  Page {page} of {totalPages}
                </p>
              )}
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
              <Table aria-label="Support tickets">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all tickets"
                      />
                    </TableHead>
                    <TableHead className="w-[100px]">Ticket</TableHead>
                    <SortableHeader
                      label="Subject"
                      sortKey="subject"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Status"
                      sortKey="status"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Priority"
                      sortKey="priority"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden md:table-cell"
                    />
                    <TableHead className="hidden md:table-cell">Category</TableHead>
                    <SortableHeader
                      label="Created"
                      sortKey="created_at"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden md:table-cell"
                    />
                    <SortableHeader
                      label="Updated"
                      sortKey="updated_at"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden md:table-cell"
                    />
                    <TableHead className="w-20 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredItems.map((ticket) => (
                    <TicketRow
                      key={ticket.id}
                      ticket={ticket}
                      selected={selectedIds.has(ticket.id)}
                      onToggle={() => toggleOne(ticket.id)}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between pt-2">
                <p className="text-xs text-muted-foreground">
                  {data!.total} total ticket{data!.total === 1 ? "" : "s"}
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
          </div>
        )}
      </PageSection>

      {/* Bulk action bar */}
      <BulkActionBar
        selectedCount={selectedIds.size}
        selectedIds={Array.from(selectedIds)}
        onClearSelection={() => setSelectedIds(new Set())}
        actions={bulkActions}
      />
    </PageContainer>
  )
}

// ── Table row ────────────────────────────────────────────────────────────

function TicketRow({
  ticket,
  selected,
  onToggle,
}: {
  ticket: Ticket
  selected: boolean
  onToggle: () => void
}) {
  return (
    <TableRow
      className={cn(!ticket.isReadByUser && "bg-primary/[0.02]")}
      data-state={selected ? "selected" : undefined}
    >
      <TableCell>
        <Checkbox
          checked={selected}
          onChange={(e) => {
            e.stopPropagation()
            onToggle()
          }}
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
            "group flex flex-col gap-0.5",
          )}
        >
          <span className={cn(
            "group-hover:underline",
            ticket.isReadByUser ? "font-medium" : "font-semibold",
          )}>
            {ticket.subject}
          </span>
          {ticket.latestMessagePreview && (
            <span className="text-xs text-muted-foreground line-clamp-1">
              {ticket.latestMessagePreview}
            </span>
          )}
        </Link>
      </TableCell>
      <TableCell>
        <TicketStatusBadge status={ticket.status} />
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <TicketPriorityBadge priority={ticket.priority} />
      </TableCell>
      <TableCell className="hidden md:table-cell">
        {ticket.category ? (
          <Badge variant="outline" className="text-xs capitalize">
            {ticket.category}
          </Badge>
        ) : (
          <span className="text-xs text-muted-foreground">--</span>
        )}
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-default text-xs text-muted-foreground">
              {formatRelativeTimeShort(ticket.createdAt)}
            </span>
          </TooltipTrigger>
          <TooltipContent>{formatDateTime(ticket.createdAt)}</TooltipContent>
        </Tooltip>
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-default text-xs text-muted-foreground">
              {formatRelativeTimeShort(ticket.updatedAt)}
            </span>
          </TooltipTrigger>
          <TooltipContent>{formatDateTime(ticket.updatedAt)}</TooltipContent>
        </Tooltip>
      </TableCell>
      <TableCell className="text-right">
        <Button asChild variant="ghost" size="sm" className="h-7 px-2 text-xs">
          <Link to="/support/$ticketId" params={{ ticketId: ticket.id }}>
            View
          </Link>
        </Button>
      </TableCell>
    </TableRow>
  )
}
