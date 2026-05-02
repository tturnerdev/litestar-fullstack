import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useState } from "react"
import {
  AlertCircle,
  Download,
  Eye,
  FileText,
  Home,
  MoreVertical,
  Search,
  Send,
  Trash2,
  X,
} from "lucide-react"
import { DirectionBadge, FaxStatusBadge } from "@/components/fax/fax-status-badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Badge } from "@/components/ui/badge"
import { BulkActionBar, createBulkDeleteAction, createExportAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { DateRangeFilter, getPresetDates, isDateInRange } from "@/components/ui/date-range-filter"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import {
  type FaxMessage,
  useDeleteFaxMessage,
  useFaxMessages,
  useFaxNumbers,
} from "@/lib/api/hooks/fax"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"

export const Route = createFileRoute("/_app/fax/messages/")({
  component: FaxMessagesPage,
})

// -- Constants ----------------------------------------------------------------

const directionOptions: FilterOption[] = [
  { value: "inbound", label: "Inbound" },
  { value: "outbound", label: "Outbound" },
]

const statusOptions: FilterOption[] = [
  { value: "received", label: "Received" },
  { value: "delivered", label: "Delivered" },
  { value: "sent", label: "Sent" },
  { value: "sending", label: "Sending" },
  { value: "queued", label: "Queued" },
  { value: "failed", label: "Failed" },
]

const PAGE_SIZE = 25

const csvHeaders: CsvHeader<FaxMessage>[] = [
  { label: "Remote Number", accessor: (m) => m.remoteNumber },
  { label: "Remote Name", accessor: (m) => m.remoteName ?? "" },
  { label: "Direction", accessor: (m) => m.direction },
  { label: "Status", accessor: (m) => m.status },
  { label: "Pages", accessor: (m) => m.pageCount },
  { label: "Error", accessor: (m) => m.errorMessage ?? "" },
  { label: "Date", accessor: (m) => { const d = m.receivedAt ?? m.createdAt; return d ? formatDateTime(d) : "" } },
]

// -- Status summary config ----------------------------------------------------

interface StatusConfig {
  label: string
  dotClass: string
  bgClass: string
  textClass: string
}

const STATUS_CONFIG: Record<string, StatusConfig> = {
  delivered: {
    label: "Delivered",
    dotClass: "bg-green-500",
    bgClass: "bg-green-500/10",
    textClass: "text-green-600 dark:text-green-400",
  },
  received: {
    label: "Received",
    dotClass: "bg-green-500",
    bgClass: "bg-green-500/10",
    textClass: "text-green-600 dark:text-green-400",
  },
  sent: {
    label: "Sent",
    dotClass: "bg-green-500",
    bgClass: "bg-green-500/10",
    textClass: "text-green-600 dark:text-green-400",
  },
  sending: {
    label: "Sending",
    dotClass: "bg-blue-500",
    bgClass: "bg-blue-500/10",
    textClass: "text-blue-600 dark:text-blue-400",
  },
  queued: {
    label: "Queued",
    dotClass: "bg-amber-500",
    bgClass: "bg-amber-500/10",
    textClass: "text-amber-600 dark:text-amber-400",
  },
  failed: {
    label: "Failed",
    dotClass: "bg-red-500",
    bgClass: "bg-red-500/10",
    textClass: "text-red-600 dark:text-red-400",
  },
}

const STATUS_DISPLAY_ORDER = ["delivered", "received", "sent", "sending", "queued", "failed"]

// -- Helpers ------------------------------------------------------------------


function formatPages(count: number): string {
  return `${count} pg${count === 1 ? "" : "s"}`
}

// -- Main page ----------------------------------------------------------------

function FaxMessagesPage() {
  useDocumentTitle("Fax Messages")
  const navigate = useNavigate()

  // Filter & search state
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [directionFilter, setDirectionFilter] = useState<string[]>([])
  const [statusFilter, setStatusFilter] = useState<string[]>([])
  const [startDate, setStartDate] = useState("")
  const [endDate, setEndDate] = useState("")
  const [page, setPage] = useState(1)

  // Reset page when debounced search changes
  useEffect(() => {
    setPage(1)
  }, [debouncedSearch])

  // Sort state
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  // Queries & mutations
  const { data: faxNumbers } = useFaxNumbers(1, 200)
  const { data, isLoading, isError, refetch } = useFaxMessages({
    page,
    pageSize: PAGE_SIZE,
    search: debouncedSearch || undefined,
    direction: directionFilter.length === 1 ? directionFilter[0] : undefined,
    status: statusFilter.length === 1 ? statusFilter[0] : undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
  })
  const deleteMessage = useDeleteFaxMessage()

  // Build a fax-number lookup map
  const faxNumberMap = useMemo(() => {
    const map = new Map<string, string>()
    if (faxNumbers?.items) {
      for (const num of faxNumbers.items) {
        map.set(num.id, num.label ?? num.number)
      }
    }
    return map
  }, [faxNumbers?.items])

  // Apply client-side filters for multi-select (API only takes single values)
  const filteredItems = useMemo(() => {
    if (!data?.items) return []
    return data.items.filter((msg) => {
      if (directionFilter.length > 1 && !directionFilter.includes(msg.direction)) return false
      if (statusFilter.length > 1 && !statusFilter.includes(msg.status)) return false
      if ((startDate || endDate) && !isDateInRange(msg.receivedAt ?? msg.createdAt, startDate, endDate))
        return false
      return true
    })
  }, [data?.items, directionFilter, statusFilter, startDate, endDate])

  // Status distribution counts from the currently visible items
  const statusCounts = useMemo(() => {
    const counts = new Map<string, number>()
    for (const msg of filteredItems) {
      counts.set(msg.status, (counts.get(msg.status) ?? 0) + 1)
    }
    return counts
  }, [filteredItems])

  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE))

  // Selection helpers
  const allVisibleIds = useMemo(() => filteredItems.map((m) => m.id), [filteredItems])
  const allSelected = filteredItems.length > 0 && filteredItems.every((m) => selectedIds.has(m.id))
  const someSelected = filteredItems.some((m) => selectedIds.has(m.id))

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

  // Reset filters helper
  const clearAllFilters = useCallback(() => {
    setSearch("")
    setDirectionFilter([])
    setStatusFilter([])
    setStartDate("")
    setEndDate("")
    setPage(1)
  }, [])

  // Export all visible
  const handleExportAll = useCallback(() => {
    if (!filteredItems.length) return
    exportToCsv("fax-messages", csvHeaders, filteredItems)
  }, [filteredItems])

  // Bulk actions
  const bulkActions = useMemo(
    () => [
      createBulkDeleteAction(
        (id) => deleteMessage.mutateAsync(id),
        () => {
          setSelectedIds(new Set())
        },
      ),
      createExportAction<FaxMessage>(
        "fax-messages-selected",
        csvHeaders,
        (ids) => filteredItems.filter((m) => ids.includes(m.id)),
      ),
    ],
    [filteredItems, deleteMessage],
  )

  // Row click handler
  const handleRowClick = useCallback(
    (messageId: string) => {
      navigate({ to: "/fax/messages/$messageId", params: { messageId } })
    },
    [navigate],
  )

  // Active filter count for display
  const activeFilterCount = directionFilter.length + statusFilter.length + (startDate || endDate ? 1 : 0)

  const hasData = filteredItems.length > 0
  const hasAnyMessages = (data?.items.length ?? 0) > 0 || !!search || activeFilterCount > 0

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
          <BreadcrumbLink asChild>
            <Link to="/fax/messages">Fax</Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          <BreadcrumbPage>Messages</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Communications"
        title="Fax Messages"
        description="View your fax history, filter by direction and status."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!hasData}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
            <Button asChild size="sm">
              <Link to="/fax/send">
                <Send className="mr-2 h-4 w-4" /> Send Fax
              </Link>
            </Button>
          </div>
        }
      />

      {/* Status distribution summary */}
      {filteredItems.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          {STATUS_DISPLAY_ORDER.filter((s) => statusCounts.has(s)).map((status) => {
            const config = STATUS_CONFIG[status]
            const count = statusCounts.get(status) ?? 0
            return (
              <span
                key={status}
                className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${config.bgClass} ${config.textClass}`}
              >
                <span className={`h-1.5 w-1.5 rounded-full ${config.dotClass}`} />
                {count} {config.label}
              </span>
            )
          })}
        </div>
      )}

      {/* Search & filters */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search by number, sender, or subject..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-8"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
              >
                <X className="h-3.5 w-3.5" />
                <span className="sr-only">Clear search</span>
              </button>
            )}
          </div>
          <FilterDropdown
            label="Direction"
            options={directionOptions}
            selected={directionFilter}
            onChange={(v) => {
              setDirectionFilter(v)
              setPage(1)
            }}
          />
          <FilterDropdown
            label="Status"
            options={statusOptions}
            selected={statusFilter}
            onChange={(v) => {
              setStatusFilter(v)
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
            label="Date"
          />
          {(activeFilterCount > 0 || search) && (
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
            title="Unable to load fax messages"
            description="Something went wrong while fetching your fax history. Please try again."
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Try again
              </Button>
            }
          />
        ) : !hasAnyMessages ? (
          <EmptyState
            icon={FileText}
            title="No fax messages yet"
            description="Your fax history will appear here once you send or receive a fax."
            action={
              <Button size="sm" asChild>
                <Link to="/fax/send">
                  <Send className="mr-2 h-4 w-4" /> Send your first fax
                </Link>
              </Button>
            }
          />
        ) : !hasData ? (
          <EmptyState
            icon={FileText}
            variant="no-results"
            title="No results found"
            description="No fax messages match your current filters. Try adjusting your search or filters."
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
                {data?.total ?? filteredItems.length} message{(data?.total ?? filteredItems.length) === 1 ? "" : "s"}
                {activeFilterCount > 0 && " (filtered)"}
              </p>
              {totalPages > 1 && (
                <p className="text-sm text-muted-foreground">
                  Page {page} of {totalPages}
                </p>
              )}
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
              <Table aria-label="Fax messages">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all messages"
                      />
                    </TableHead>
                    <SortableHeader
                      label="Date"
                      sortKey="received_at"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden md:table-cell"
                    />
                    <SortableHeader
                      label="Direction"
                      sortKey="direction"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden md:table-cell"
                    />
                    <SortableHeader
                      label="Remote Number"
                      sortKey="remote_number"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <TableHead className="hidden md:table-cell">Fax Line</TableHead>
                    <TableHead className="hidden md:table-cell">Pages</TableHead>
                    <SortableHeader
                      label="Status"
                      sortKey="status"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <TableHead className="w-16 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredItems.map((msg, index) => (
                    <FaxMessageRow
                      key={msg.id}
                      msg={msg}
                      index={index}
                      faxLineName={faxNumberMap.get(msg.faxNumberId) ?? ""}
                      selected={selectedIds.has(msg.id)}
                      onToggle={() => toggleOne(msg.id)}
                      onRowClick={() => handleRowClick(msg.id)}
                      onDelete={() => deleteMessage.mutate(msg.id)}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-end gap-2">
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

// -- Table row ----------------------------------------------------------------

function FaxMessageRow({
  msg,
  index,
  faxLineName,
  selected,
  onToggle,
  onRowClick,
  onDelete,
}: {
  msg: FaxMessage
  index: number
  faxLineName: string
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
  onDelete: () => void
}) {
  return (
    <TableRow
      data-state={selected ? "selected" : undefined}
      className={`cursor-pointer hover:bg-muted/50 transition-colors ${index % 2 === 1 ? "bg-muted/20" : ""}`}
      onClick={(e) => {
        const target = e.target as HTMLElement
        if (target.closest("[role=checkbox]") || target.closest("[data-slot=dropdown]") || target.closest("button") || target.closest("a")) {
          return
        }
        onRowClick()
      }}
    >
      <TableCell>
        <Checkbox
          checked={selected}
          onChange={(e) => {
            e.stopPropagation()
            onToggle()
          }}
          aria-label={`Select message from ${msg.remoteNumber}`}
        />
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-default whitespace-nowrap text-xs text-muted-foreground">
              {formatRelativeTimeShort(msg.receivedAt ?? msg.createdAt)}
            </span>
          </TooltipTrigger>
          <TooltipContent>{formatDateTime(msg.receivedAt ?? msg.createdAt)}</TooltipContent>
        </Tooltip>
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <DirectionBadge direction={msg.direction} />
      </TableCell>
      <TableCell>
        <div className="flex flex-col gap-0.5">
          <Link
            to="/fax/messages/$messageId"
            params={{ messageId: msg.id }}
            className="font-mono text-sm hover:underline"
            onClick={(e) => e.stopPropagation()}
          >
            {msg.remoteNumber}
          </Link>
          {msg.remoteName && (
            <span className="text-xs text-muted-foreground">{msg.remoteName}</span>
          )}
        </div>
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <span className="text-sm text-muted-foreground">{faxLineName || "--"}</span>
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <Badge variant="outline" className="font-mono text-xs">
          {formatPages(msg.pageCount)}
        </Badge>
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-2">
          <FaxStatusBadge status={msg.status} />
          {msg.errorMessage && (
            <Tooltip>
              <TooltipTrigger asChild>
                <AlertCircle className="h-3.5 w-3.5 cursor-help text-destructive" />
              </TooltipTrigger>
              <TooltipContent className="max-w-xs">{msg.errorMessage}</TooltipContent>
            </Tooltip>
          )}
        </div>
      </TableCell>
      <TableCell className="text-right">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 w-8 p-0"
              data-slot="dropdown"
              onClick={(e) => e.stopPropagation()}
            >
              <MoreVertical className="h-4 w-4" />
              <span className="sr-only">Actions for message from {msg.remoteNumber}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link to="/fax/messages/$messageId" params={{ messageId: msg.id }}>
                <Eye className="mr-2 h-4 w-4" />
                View details
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <a href={`/api/fax/messages/${msg.id}/download`} target="_blank" rel="noopener noreferrer">
                <Download className="mr-2 h-4 w-4" />
                Download
              </a>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="text-destructive focus:text-destructive"
              onClick={onDelete}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  )
}
