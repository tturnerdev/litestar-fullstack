import { createFileRoute, Link } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import {
  AlertCircle,
  Download,
  Eye,
  FileText,
  Home,
  MoreVertical,
  Search,
  Send,
  SlidersHorizontal,
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
import { DataFreshness } from "@/components/ui/data-freshness"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { DateRangeFilter, getPresetDates, isDateInRange } from "@/components/ui/date-range-filter"
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
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
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { useSettingsStore } from "@/lib/settings-store"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/fax/messages/")({
  validateSearch: (
    search: Record<string, unknown>,
  ): {
    q?: string
    page?: number
    number?: string
    direction?: string
    status?: string
    sort?: string
    order?: string
  } => ({
    q: typeof search.q === "string" && search.q ? search.q : undefined,
    page: Number(search.page) > 1 ? Number(search.page) : undefined,
    number: typeof search.number === "string" && search.number ? search.number : undefined,
    direction: typeof search.direction === "string" && search.direction ? search.direction : undefined,
    status: typeof search.status === "string" && search.status ? search.status : undefined,
    sort: typeof search.sort === "string" && search.sort ? search.sort : undefined,
    order:
      typeof search.order === "string" && (search.order === "asc" || search.order === "desc")
        ? search.order
        : undefined,
  }),
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

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_STORAGE_KEY = "fax-messages-page-size"
const AUTO_REFRESH_STORAGE_KEY = "fax-messages-auto-refresh"
const AUTO_REFRESH_INTERVAL = 30_000

function getStoredPageSize(): number {
  try {
    const stored = localStorage.getItem(PAGE_SIZE_STORAGE_KEY)
    if (stored) {
      const parsed = Number(stored)
      if ((PAGE_SIZES as readonly number[]).includes(parsed)) return parsed
    }
  } catch {
    // localStorage unavailable
  }
  return DEFAULT_PAGE_SIZE
}

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

// -- Column visibility ---------------------------------------------------------

const COLUMN_VISIBILITY_KEY = "fax-messages-columns"

const TOGGLEABLE_COLUMNS = [
  { key: "direction", label: "Direction" },
  { key: "status", label: "Status" },
  { key: "pages", label: "Pages" },
  { key: "faxLine", label: "Fax Line" },
  { key: "created", label: "Date" },
] as const

type ColumnVisibility = Record<string, boolean>

function loadColumnVisibility(): ColumnVisibility {
  try {
    return JSON.parse(localStorage.getItem(COLUMN_VISIBILITY_KEY) ?? "{}")
  } catch {
    return {}
  }
}

// -- Helpers ------------------------------------------------------------------


function formatPages(count: number): string {
  return `${count} pg${count === 1 ? "" : "s"}`
}

// -- Main page ----------------------------------------------------------------

function FaxMessagesPage() {
  useDocumentTitle("Fax Messages")
  const compactMode = useSettingsStore((s) => s.compactMode)
  const cellClass = compactMode ? "py-1 px-2 text-xs" : ""
  const {
    q: searchParam,
    page: pageParam,
    direction: directionParam,
    status: statusParam,
    sort: sortParam,
    order: orderParam,
  } = Route.useSearch()
  const navigate = Route.useNavigate()
  const searchInputRef = useRef<HTMLInputElement>(null)

  // Derive filter state from URL search params
  const search = searchParam ?? ""
  const page = pageParam ?? 1
  const directionFilter = useMemo(
    () => (directionParam ? directionParam.split(",").filter(Boolean) : []),
    [directionParam],
  )
  const statusFilter = useMemo(
    () => (statusParam ? statusParam.split(",").filter(Boolean) : []),
    [statusParam],
  )
  const sortKey = sortParam ?? null
  const sortDir: SortDirection = (orderParam as SortDirection) ?? null

  // Local input state for search (so typing is smooth before debounce)
  const [searchInput, setSearchInput] = useState(search)
  const debouncedSearch = useDebouncedValue(searchInput)

  // Sync URL when debounced search value settles
  useEffect(() => {
    navigate({
      search: (prev) => ({
        ...prev,
        q: debouncedSearch || undefined,
        page: undefined,
      }),
      replace: true,
    })
  }, [debouncedSearch, navigate])

  // Keep local input in sync if URL search param changes externally (back/forward)
  useEffect(() => {
    setSearchInput(search)
  }, [search])

  // Column visibility
  const [columnVisibility, setColumnVisibility] = useState<ColumnVisibility>(loadColumnVisibility)
  const isColumnVisible = useCallback(
    (col: string) => columnVisibility[col] !== false,
    [columnVisibility],
  )
  const toggleColumn = useCallback((col: string) => {
    setColumnVisibility((prev) => {
      const updated = { ...prev, [col]: prev[col] !== false ? false : true }
      localStorage.setItem(COLUMN_VISIBILITY_KEY, JSON.stringify(updated))
      return updated
    })
  }, [])

  // Auto-refresh state
  const [autoRefresh, setAutoRefresh] = useState(() => {
    try {
      return localStorage.getItem(AUTO_REFRESH_STORAGE_KEY) === "true"
    } catch {
      return false
    }
  })

  const toggleAutoRefresh = useCallback(() => {
    setAutoRefresh((prev) => {
      const next = !prev
      try {
        localStorage.setItem(AUTO_REFRESH_STORAGE_KEY, String(next))
      } catch {
        // localStorage unavailable
      }
      return next
    })
  }, [])

  // Date range state (client-side only, not in URL)
  const [startDate, setStartDate] = useState("")
  const [endDate, setEndDate] = useState("")
  const [pageSize, setPageSize] = useState(getStoredPageSize)

  // Persist page size preference
  const handlePageSizeChange = useCallback(
    (value: string) => {
      const size = Number(value)
      setPageSize(size)
      navigate({ search: (prev) => ({ ...prev, page: undefined }), replace: true })
      try {
        localStorage.setItem(PAGE_SIZE_STORAGE_KEY, value)
      } catch {
        // localStorage unavailable
      }
    },
    [navigate],
  )

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  // Queries & mutations
  const { data: faxNumbers } = useFaxNumbers(1, 200)
  const { data, isLoading, isError, refetch, dataUpdatedAt, isRefetching } = useFaxMessages({
    page,
    pageSize,
    search: debouncedSearch || undefined,
    direction: directionFilter.length === 1 ? directionFilter[0] : undefined,
    status: statusFilter.length === 1 ? statusFilter[0] : undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
    refetchInterval: autoRefresh ? AUTO_REFRESH_INTERVAL : false,
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

  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / pageSize))

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
      navigate({
        search: (prev) => ({
          ...prev,
          sort: next.sort || undefined,
          order: next.direction || undefined,
        }),
      })
    },
    [sortKey, sortDir, navigate],
  )

  // Date range handler
  const handleDatePreset = useCallback(
    (days: number) => {
      const { start, end } = getPresetDates(days)
      setStartDate(start)
      setEndDate(end)
      navigate({ search: (prev) => ({ ...prev, page: undefined }) })
    },
    [navigate],
  )

  // Reset filters helper
  const clearAllFilters = useCallback(() => {
    setSearchInput("")
    setStartDate("")
    setEndDate("")
    navigate({
      search: {
        q: undefined,
        number: undefined,
        direction: undefined,
        status: undefined,
        sort: undefined,
        order: undefined,
        page: undefined,
      },
    })
  }, [navigate])

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

  // Keyboard shortcuts: "/" to focus search, ArrowLeft/ArrowRight for pagination
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return
      if (e.key === "/" && !e.ctrlKey && !e.metaKey) {
        e.preventDefault()
        searchInputRef.current?.focus()
      }
      if (e.key === "ArrowLeft" && page > 1) {
        e.preventDefault()
        navigate({ search: (prev) => ({ ...prev, page: page - 1 > 1 ? page - 1 : undefined }) })
      }
      if (e.key === "ArrowRight" && page < totalPages) {
        e.preventDefault()
        navigate({ search: (prev) => ({ ...prev, page: page + 1 }) })
      }
    }
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [page, totalPages, navigate])

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
            <DataFreshness
              dataUpdatedAt={dataUpdatedAt}
              onRefresh={() => refetch()}
              isRefreshing={isRefetching}
            />
            <Button
              variant={autoRefresh ? "default" : "outline"}
              size="sm"
              onClick={toggleAutoRefresh}
            >
              {autoRefresh && (
                <span className="mr-2 h-2 w-2 animate-pulse rounded-full bg-emerald-500" />
              )}
              Live
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <SlidersHorizontal className="mr-1.5 h-3.5 w-3.5" />
                  Columns
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-44">
                <DropdownMenuLabel>Toggle columns</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {TOGGLEABLE_COLUMNS.map((col) => (
                  <DropdownMenuCheckboxItem
                    key={col.key}
                    checked={isColumnVisible(col.key)}
                    onCheckedChange={() => toggleColumn(col.key)}
                  >
                    {col.label}
                  </DropdownMenuCheckboxItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
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
      <SectionErrorBoundary name="Fax Messages Summary">
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
      </SectionErrorBoundary>

      {/* Search & filters */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              ref={searchInputRef}
              placeholder="Search by number, sender, or subject..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              className="pl-9 pr-8"
            />
            {searchInput ? (
              <button
                type="button"
                onClick={() => setSearchInput("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
              >
                <X className="h-3.5 w-3.5" />
                <span className="sr-only">Clear search</span>
              </button>
            ) : (
              <kbd className="pointer-events-none absolute right-8 top-1/2 -translate-y-1/2 hidden rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground sm:inline">/</kbd>
            )}
          </div>
          <FilterDropdown
            label="Direction"
            options={directionOptions}
            selected={directionFilter}
            onChange={(v) => {
              navigate({
                search: (prev) => ({
                  ...prev,
                  direction: v.length > 0 ? v.join(",") : undefined,
                  page: undefined,
                }),
              })
            }}
          />
          <FilterDropdown
            label="Status"
            options={statusOptions}
            selected={statusFilter}
            onChange={(v) => {
              navigate({
                search: (prev) => ({
                  ...prev,
                  status: v.length > 0 ? v.join(",") : undefined,
                  page: undefined,
                }),
              })
            }}
          />
          <DateRangeFilter
            startDate={startDate}
            endDate={endDate}
            onStartDateChange={(v) => {
              setStartDate(v)
              navigate({ search: (prev) => ({ ...prev, page: undefined }) })
            }}
            onEndDateChange={(v) => {
              setEndDate(v)
              navigate({ search: (prev) => ({ ...prev, page: undefined }) })
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
        <SectionErrorBoundary name="Fax Messages Table">
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

            <div className="sr-only" aria-live="polite" aria-atomic="true">
              {!isLoading && `Showing ${filteredItems.length} of ${data?.total ?? 0} fax messages, page ${page}`}
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
              <Table aria-label="Fax messages" aria-busy={isLoading || isRefetching}>
                <TableHeader className="sticky top-0 z-10 bg-background">
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all messages"
                      />
                    </TableHead>
                    {isColumnVisible("created") && (
                      <SortableHeader
                        label="Date"
                        sortKey="received_at"
                        currentSort={sortKey}
                        currentDirection={sortDir}
                        onSort={handleSort}
                        className="hidden md:table-cell"
                      />
                    )}
                    {isColumnVisible("direction") && (
                      <SortableHeader
                        label="Direction"
                        sortKey="direction"
                        currentSort={sortKey}
                        currentDirection={sortDir}
                        onSort={handleSort}
                        className="hidden md:table-cell"
                      />
                    )}
                    <SortableHeader
                      label="Remote Number"
                      sortKey="remote_number"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    {isColumnVisible("faxLine") && (
                      <TableHead className="hidden md:table-cell">Fax Line</TableHead>
                    )}
                    {isColumnVisible("pages") && (
                      <TableHead className="hidden md:table-cell">Pages</TableHead>
                    )}
                    {isColumnVisible("status") && (
                      <SortableHeader
                        label="Status"
                        sortKey="status"
                        currentSort={sortKey}
                        currentDirection={sortDir}
                        onSort={handleSort}
                      />
                    )}
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
                      cellClass={cellClass}
                      isColumnVisible={isColumnVisible}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>

            {/* Pagination */}
            <div className="flex items-center justify-end gap-4">
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">Rows per page</span>
                <Select value={String(pageSize)} onValueChange={handlePageSizeChange}>
                  <SelectTrigger className="h-8 w-[70px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {PAGE_SIZES.map((size) => (
                      <SelectItem key={size} value={String(size)}>
                        {size}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {totalPages > 1 && (
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      navigate({
                        search: (prev) => ({
                          ...prev,
                          page: page - 1 > 1 ? page - 1 : undefined,
                        }),
                      })
                    }
                    disabled={page <= 1}
                  >
                    Previous
                    <kbd className="ml-1.5 hidden rounded border border-border bg-muted px-1 py-0.5 text-[10px] font-medium text-muted-foreground lg:inline">&larr;</kbd>
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      navigate({
                        search: (prev) => ({ ...prev, page: page + 1 }),
                      })
                    }
                    disabled={page >= totalPages}
                  >
                    Next
                    <kbd className="ml-1.5 hidden rounded border border-border bg-muted px-1 py-0.5 text-[10px] font-medium text-muted-foreground lg:inline">&rarr;</kbd>
                  </Button>
                </div>
              )}
            </div>
          </div>
        )}
        </SectionErrorBoundary>
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
  cellClass,
  isColumnVisible,
}: {
  msg: FaxMessage
  index: number
  faxLineName: string
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
  onDelete: () => void
  cellClass: string
  isColumnVisible: (col: string) => boolean
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
      <TableCell className={cellClass}>
        <Checkbox
          checked={selected}
          onChange={(e) => {
            e.stopPropagation()
            onToggle()
          }}
          aria-label={`Select message from ${msg.remoteNumber}`}
        />
      </TableCell>
      {isColumnVisible("created") && (
        <TableCell className={cn("hidden md:table-cell", cellClass)}>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="cursor-default whitespace-nowrap text-xs text-muted-foreground">
                {formatRelativeTimeShort(msg.receivedAt ?? msg.createdAt)}
              </span>
            </TooltipTrigger>
            <TooltipContent>{formatDateTime(msg.receivedAt ?? msg.createdAt)}</TooltipContent>
          </Tooltip>
        </TableCell>
      )}
      {isColumnVisible("direction") && (
        <TableCell className={cn("hidden md:table-cell", cellClass)}>
          <DirectionBadge direction={msg.direction} />
        </TableCell>
      )}
      <TableCell className={cellClass}>
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
      {isColumnVisible("faxLine") && (
        <TableCell className={cn("hidden md:table-cell", cellClass)}>
          <span className="text-sm text-muted-foreground">{faxLineName || "--"}</span>
        </TableCell>
      )}
      {isColumnVisible("pages") && (
        <TableCell className={cn("hidden md:table-cell", cellClass)}>
          <Badge variant="outline" className="font-mono text-xs">
            {formatPages(msg.pageCount)}
          </Badge>
        </TableCell>
      )}
      {isColumnVisible("status") && (
        <TableCell className={cellClass}>
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
      )}
      <TableCell className={cn("text-right", cellClass)}>
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
