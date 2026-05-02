import { createFileRoute, Link } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import {
  AlertCircle,
  Download,
  Eye,
  Filter,
  Home,
  Monitor,
  MoreVertical,
  Pencil,
  Plus,
  Power,
  RefreshCw,
  RotateCcw,
  Search,
  SlidersHorizontal,
  Trash2,
  X,
} from "lucide-react"
import { DataFreshness } from "@/components/ui/data-freshness"
import { DeviceStatusBadge } from "@/components/devices/device-status-badge"
import { Badge } from "@/components/ui/badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { BulkActionBar, createBulkDeleteAction, createExportAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { DateRangeFilter, getPresetDates, isDateInRange } from "@/components/ui/date-range-filter"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton, SkeletonCard } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import {
  useDevices,
  useDeleteDevice,
  useRebootDevice,
  useReprovisionDevice,
  useUpdateDevice,
} from "@/lib/api/hooks/devices"
import { deleteDevice, type Device } from "@/lib/generated/api"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { useSettingsStore } from "@/lib/settings-store"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/devices/")({
  validateSearch: (
    search: Record<string, unknown>,
  ): {
    q?: string
    page?: number
    status?: string
    type?: string
    sort?: string
    order?: string
  } => ({
    q: typeof search.q === "string" && search.q ? search.q : undefined,
    page: Number(search.page) > 1 ? Number(search.page) : undefined,
    status: typeof search.status === "string" && search.status ? search.status : undefined,
    type: typeof search.type === "string" && search.type ? search.type : undefined,
    sort: typeof search.sort === "string" && search.sort ? search.sort : undefined,
    order:
      typeof search.order === "string" && (search.order === "asc" || search.order === "desc")
        ? search.order
        : undefined,
  }),
  component: DevicesPage,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_STORAGE_KEY = "devices-page-size"
const AUTO_REFRESH_STORAGE_KEY = "devices-auto-refresh"
const AUTO_REFRESH_INTERVAL = 10_000

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

const deviceTypeLabels: Record<string, string> = {
  desk_phone: "Desk Phone",
  softphone: "Softphone",
  ata: "ATA",
  conference: "Conference",
  gateway: "Gateway",
  other: "Other",
}

const deviceTypeOptions: FilterOption[] = [
  { value: "desk_phone", label: "Desk Phone" },
  { value: "softphone", label: "Softphone" },
  { value: "ata", label: "ATA" },
  { value: "conference", label: "Conference" },
  { value: "gateway", label: "Gateway" },
  { value: "other", label: "Other" },
]

const statusOptions: FilterOption[] = [
  { value: "online", label: "Online" },
  { value: "offline", label: "Offline" },
  { value: "ringing", label: "Ringing" },
  { value: "in_use", label: "In Use" },
  { value: "provisioning", label: "Provisioning" },
  { value: "error", label: "Error" },
]

const csvHeaders: CsvHeader<Device>[] = [
  { label: "Name", accessor: (d) => d.name },
  { label: "Type", accessor: (d) => deviceTypeLabels[d.deviceType] ?? d.deviceType },
  { label: "Status", accessor: (d) => d.status },
  { label: "MAC Address", accessor: (d) => d.macAddress ?? "" },
  { label: "Model", accessor: (d) => d.deviceModel ?? "" },
  { label: "IP Address", accessor: (d) => d.ipAddress ?? "" },
  { label: "Last Seen", accessor: (d) => (d.lastSeenAt ? formatDateTime(d.lastSeenAt) : "Never") },
  { label: "Active", accessor: (d) => (d.isActive === false ? "No" : "Yes") },
]

// -- Quick filter chips -------------------------------------------------------

interface QuickFilter {
  id: string
  label: string
  statuses: string[]
}

const QUICK_FILTERS: QuickFilter[] = [
  { id: "online", label: "Online Only", statuses: ["online", "ringing", "in_use"] },
  { id: "offline", label: "Offline", statuses: ["offline"] },
  { id: "attention", label: "Needs Attention", statuses: ["error", "provisioning"] },
]

function isQuickFilterActive(filter: QuickFilter, statusFilter: string[]): boolean {
  if (statusFilter.length !== filter.statuses.length) return false
  return filter.statuses.every((s) => statusFilter.includes(s))
}

// -- Column visibility ---------------------------------------------------------

const COLUMN_VISIBILITY_KEY = "devices-columns"

const TOGGLEABLE_COLUMNS = [
  { key: "status", label: "Status" },
  { key: "type", label: "Type" },
  { key: "mac", label: "MAC Address" },
  { key: "ip", label: "IP Address" },
  { key: "lastSeen", label: "Last Seen" },
] as const

type ColumnVisibility = Record<string, boolean>

function loadColumnVisibility(): ColumnVisibility {
  try {
    return JSON.parse(localStorage.getItem(COLUMN_VISIBILITY_KEY) ?? "{}")
  } catch {
    return {}
  }
}

// -- Main page ----------------------------------------------------------------

function DevicesPage() {
  useDocumentTitle("Devices")
  const compactMode = useSettingsStore((s) => s.compactMode)
  const cellClass = compactMode ? "py-1 px-2 text-xs" : ""
  const {
    q: searchParam,
    page: pageParam,
    status: statusParam,
    type: typeParam,
    sort: sortParam,
    order: orderParam,
  } = Route.useSearch()
  const navigate = Route.useNavigate()
  const searchInputRef = useRef<HTMLInputElement>(null)

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

  // Derive filter state from URL search params
  const search = searchParam ?? ""
  const page = pageParam ?? 1
  const statusFilter = useMemo(
    () => (statusParam ? statusParam.split(",").filter(Boolean) : []),
    [statusParam],
  )
  const typeFilter = useMemo(
    () => (typeParam ? typeParam.split(",").filter(Boolean) : []),
    [typeParam],
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
  const { data, isLoading, isError, refetch, dataUpdatedAt, isRefetching } = useDevices({
    page,
    pageSize,
    search: debouncedSearch || undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
    refetchInterval: autoRefresh ? AUTO_REFRESH_INTERVAL : false,
  })
  const deleteMutation = useDeleteDevice()

  // Apply client-side type & status filters
  const filteredItems = useMemo(() => {
    if (!data?.items) return []
    return data.items.filter((device) => {
      if (typeFilter.length > 0 && !typeFilter.includes(device.deviceType)) return false
      if (statusFilter.length > 0 && !statusFilter.includes(device.status)) return false
      if ((startDate || endDate) && !isDateInRange(device.lastSeenAt, startDate, endDate))
        return false
      return true
    })
  }, [data?.items, typeFilter, statusFilter, startDate, endDate])

  // Device status summary stats (computed from ALL items on the current page)
  const deviceStats = useMemo(() => {
    const items = data?.items ?? []
    let online = 0
    let offline = 0
    let provisioning = 0
    let error = 0
    for (const device of items) {
      switch (device.status) {
        case "online":
        case "ringing":
        case "in_use":
          online++
          break
        case "offline":
          offline++
          break
        case "provisioning":
          provisioning++
          break
        case "error":
          error++
          break
      }
    }
    return { online, offline, provisioning, error, total: data?.total ?? 0 }
  }, [data?.items, data?.total])

  // Selection helpers
  const allVisibleIds = useMemo(() => filteredItems.map((d) => d.id), [filteredItems])
  const allSelected = filteredItems.length > 0 && filteredItems.every((d) => selectedIds.has(d.id))
  const someSelected = filteredItems.some((d) => selectedIds.has(d.id))

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

  // Bulk actions
  const bulkActions = useMemo(
    () => [
      createBulkDeleteAction(
        async (id) => {
          await deleteDevice({ path: { device_id: id } })
        },
        () => {
          setSelectedIds(new Set())
          deleteMutation.reset()
        },
      ),
      createExportAction<Device>(
        "devices-selected",
        csvHeaders,
        (ids) => filteredItems.filter((d) => ids.includes(d.id)),
      ),
    ],
    [filteredItems, deleteMutation],
  )

  // Export all visible
  const handleExportAll = useCallback(() => {
    if (!filteredItems.length) return
    exportToCsv("devices", csvHeaders, filteredItems)
  }, [filteredItems])

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

  // Quick filter chip toggle
  const handleQuickFilter = useCallback(
    (filter: QuickFilter) => {
      const nextStatuses = isQuickFilterActive(filter, statusFilter) ? [] : filter.statuses
      navigate({
        search: (prev) => ({
          ...prev,
          status: nextStatuses.length > 0 ? nextStatuses.join(",") : undefined,
          page: undefined,
        }),
      })
    },
    [statusFilter, navigate],
  )

  // Row click handler
  const handleRowClick = useCallback(
    (deviceId: string) => {
      navigate({ to: "/devices/$deviceId", params: { deviceId } })
    },
    [navigate],
  )

  // Active filter count for display
  const activeFilterCount = typeFilter.length + statusFilter.length + (startDate || endDate ? 1 : 0)

  const hasData = filteredItems.length > 0
  const hasAnyDevices = (data?.items.length ?? 0) > 0
  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / pageSize))

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
          <BreadcrumbPage>Devices</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Workspace"
        title="Devices"
        description="Manage your phones, softphones, and other SIP devices."
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
            <Button size="sm" asChild>
              <Link to="/devices/new">
                <Plus className="mr-2 h-4 w-4" /> Add device
              </Link>
            </Button>
          </div>
        }
      />

      {/* Status summary pills */}
      <SectionErrorBoundary name="Device Status Summary">
      <div className="flex flex-wrap items-center gap-2">
        {isLoading ? (
          <>
            <Skeleton className="h-7 w-24 rounded-full" />
            <Skeleton className="h-7 w-24 rounded-full" />
            <Skeleton className="h-7 w-24 rounded-full" />
          </>
        ) : (
          <>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-muted/50 px-3 py-1 text-xs font-medium text-muted-foreground">
              Total
              <span className="ml-0.5 font-semibold text-foreground">{deviceStats.total}</span>
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
              Online
              <span className="ml-0.5 font-semibold">{deviceStats.online}</span>
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-red-500/30 bg-red-500/10 px-3 py-1 text-xs font-medium text-red-700 dark:text-red-400">
              <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
              Offline
              <span className="ml-0.5 font-semibold">{deviceStats.offline}</span>
            </span>
            {deviceStats.provisioning > 0 && (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1 text-xs font-medium text-amber-700 dark:text-amber-400">
                <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
                Provisioning
                <span className="ml-0.5 font-semibold">{deviceStats.provisioning}</span>
              </span>
            )}
            {deviceStats.error > 0 && (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-rose-500/30 bg-rose-500/10 px-3 py-1 text-xs font-medium text-rose-700 dark:text-rose-400">
                <span className="h-1.5 w-1.5 rounded-full bg-rose-500" />
                Error
                <span className="ml-0.5 font-semibold">{deviceStats.error}</span>
              </span>
            )}
          </>
        )}
      </div>
      </SectionErrorBoundary>

      {/* Quick filter chips */}
      <div className="flex flex-wrap items-center gap-2">
        <Filter className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
        {QUICK_FILTERS.map((filter) => {
          const active = isQuickFilterActive(filter, statusFilter)
          return (
            <Button
              key={filter.id}
              variant={active ? "default" : "outline"}
              size="sm"
              className="h-7 rounded-full text-xs"
              onClick={() => handleQuickFilter(filter)}
            >
              {filter.label}
              {active && <X className="ml-1.5 h-3 w-3" />}
            </Button>
          )
        })}
      </div>

      {/* Search & filters */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              ref={searchInputRef}
              placeholder="Search by name, MAC address, or model..."
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
            label="Type"
            options={deviceTypeOptions}
            selected={typeFilter}
            onChange={(v) => {
              navigate({
                search: (prev) => ({
                  ...prev,
                  type: v.length > 0 ? v.join(",") : undefined,
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
            label="Last seen"
          />
          {activeFilterCount > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="text-xs text-muted-foreground"
              onClick={() => {
                setStartDate("")
                setEndDate("")
                navigate({
                  search: (prev) => ({
                    ...prev,
                    type: undefined,
                    status: undefined,
                    page: undefined,
                  }),
                })
              }}
            >
              Clear all filters
            </Button>
          )}
        </div>
      </PageSection>

      {/* Content */}
      <PageSection delay={0.1}>
        <SectionErrorBoundary name="Devices Table">
        {isLoading ? (
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <SkeletonCard key={i} />
            ))}
          </div>
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load devices"
            description="Something went wrong while fetching your devices. Please try again."
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Try again
              </Button>
            }
          />
        ) : !hasAnyDevices && !search && activeFilterCount === 0 ? (
          <EmptyState
            icon={Monitor}
            title="No devices yet"
            description="Add your first device to start managing phones, ATAs, and other SIP endpoints."
            action={
              <Button size="sm" asChild>
                <Link to="/devices/new">
                  <Plus className="mr-2 h-4 w-4" /> Add device
                </Link>
              </Button>
            }
          />
        ) : !hasData ? (
          <EmptyState
            icon={Monitor}
            variant="no-results"
            title="No results found"
            description="No devices match your current filters. Try adjusting your search or filters."
            action={
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setSearchInput("")
                  setStartDate("")
                  setEndDate("")
                  navigate({
                    search: {
                      q: undefined,
                      type: undefined,
                      status: undefined,
                      sort: undefined,
                      order: undefined,
                      page: undefined,
                    },
                  })
                }}
              >
                Clear all filters
              </Button>
            }
          />
        ) : (
          <div className="space-y-3">
            {/* Result count & pagination info */}
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">
                {data?.total ?? filteredItems.length} device{(data?.total ?? filteredItems.length) === 1 ? "" : "s"}
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
              <Table aria-label="Devices" aria-busy={isLoading || isRefetching}>
                <TableHeader className="sticky top-0 z-10 bg-background">
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all devices"
                      />
                    </TableHead>
                    <SortableHeader
                      label="Name"
                      sortKey="name"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    {isColumnVisible("type") && (
                      <SortableHeader
                        label="Type"
                        sortKey="device_type"
                        currentSort={sortKey}
                        currentDirection={sortDir}
                        onSort={handleSort}
                        className="hidden md:table-cell"
                      />
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
                    {isColumnVisible("mac") && (
                      <TableHead className="hidden md:table-cell">MAC Address</TableHead>
                    )}
                    {isColumnVisible("ip") && (
                      <SortableHeader
                        label="IP Address"
                        sortKey="ip_address"
                        currentSort={sortKey}
                        currentDirection={sortDir}
                        onSort={handleSort}
                        className="hidden md:table-cell"
                      />
                    )}
                    {isColumnVisible("lastSeen") && (
                      <SortableHeader
                        label="Last Seen"
                        sortKey="last_seen_at"
                        currentSort={sortKey}
                        currentDirection={sortDir}
                        onSort={handleSort}
                        className="hidden md:table-cell"
                      />
                    )}
                    <TableHead className="w-16 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredItems.map((device, index) => (
                    <DeviceRow
                      key={device.id}
                      device={device}
                      index={index}
                      selected={selectedIds.has(device.id)}
                      onToggle={() => toggleOne(device.id)}
                      onRowClick={() => handleRowClick(device.id)}
                      onDelete={() => deleteMutation.mutate(device.id)}
                      cellClass={cellClass}
                      isColumnVisible={isColumnVisible}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className="sr-only" aria-live="polite" aria-atomic="true">
              {!isLoading && `Showing ${filteredItems.length} of ${data?.total ?? 0} results, page ${page}`}
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

            {/* Keyboard shortcut hints */}
            <div className="hidden items-center justify-center gap-4 pt-1 text-[11px] text-muted-foreground/60 lg:flex">
              <span className="inline-flex items-center gap-1.5">
                <kbd className="inline-flex h-5 min-w-5 items-center justify-center rounded border border-border/50 bg-muted/50 px-1 font-mono text-[10px] font-medium">/</kbd>
                Search
              </span>
              <span className="inline-flex items-center gap-1.5">
                <kbd className="inline-flex h-5 min-w-5 items-center justify-center rounded border border-border/50 bg-muted/50 px-1 font-mono text-[10px] font-medium">&larr;</kbd>
                <kbd className="inline-flex h-5 min-w-5 items-center justify-center rounded border border-border/50 bg-muted/50 px-1 font-mono text-[10px] font-medium">&rarr;</kbd>
                Navigate pages
              </span>
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

function DeviceRow({
  device,
  index,
  selected,
  onToggle,
  onRowClick,
  onDelete,
  cellClass,
  isColumnVisible,
}: {
  device: Device
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
  onDelete: () => void
  cellClass: string
  isColumnVisible: (col: string) => boolean
}) {
  const rebootMutation = useRebootDevice(device.id)
  const reprovisionMutation = useReprovisionDevice(device.id)
  const updateMutation = useUpdateDevice(device.id)

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
          aria-label={`Select ${device.name}`}
        />
      </TableCell>
      <TableCell className={cellClass}>
        <Link
          to="/devices/$deviceId"
          params={{ deviceId: device.id }}
          className="group flex flex-col gap-0.5"
          onClick={(e) => e.stopPropagation()}
        >
          <span className="font-medium group-hover:underline">{device.name}</span>
          {device.deviceModel && (
            <span className="text-xs text-muted-foreground">
              {device.manufacturer ? `${device.manufacturer} ` : ""}
              {device.deviceModel}
            </span>
          )}
        </Link>
        {device.isActive === false && (
          <Badge variant="outline" className="ml-2 border-muted-foreground/30 text-muted-foreground text-[10px]">
            Disabled
          </Badge>
        )}
      </TableCell>
      {isColumnVisible("type") && (
        <TableCell className={cn("hidden md:table-cell", cellClass)}>
          <Badge variant="outline">
            {deviceTypeLabels[device.deviceType] ?? device.deviceType}
          </Badge>
        </TableCell>
      )}
      {isColumnVisible("status") && (
        <TableCell className={cellClass}>
          <DeviceStatusBadge status={device.status} />
        </TableCell>
      )}
      {isColumnVisible("mac") && (
        <TableCell className={cn("hidden md:table-cell", cellClass)}>
          {device.macAddress ? (
            <span className="font-mono text-xs text-muted-foreground">{device.macAddress}</span>
          ) : (
            <span className="text-xs text-muted-foreground">--</span>
          )}
        </TableCell>
      )}
      {isColumnVisible("ip") && (
        <TableCell className={cn("hidden md:table-cell", cellClass)}>
          {device.ipAddress ? (
            <span className="font-mono text-xs text-muted-foreground">{device.ipAddress}</span>
          ) : (
            <span className="text-xs text-muted-foreground">--</span>
          )}
        </TableCell>
      )}
      {isColumnVisible("lastSeen") && (
        <TableCell className={cn("hidden md:table-cell", cellClass)}>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="text-xs text-muted-foreground">
                {formatRelativeTimeShort(device.lastSeenAt)}
              </span>
            </TooltipTrigger>
            <TooltipContent>{formatDateTime(device.lastSeenAt)}</TooltipContent>
          </Tooltip>
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
              <span className="sr-only">Actions for {device.name}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link to="/devices/$deviceId" params={{ deviceId: device.id }}>
                <Eye className="mr-2 h-4 w-4" />
                View details
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link to="/devices/$deviceId" params={{ deviceId: device.id }} search={{ edit: true }}>
                <Pencil className="mr-2 h-4 w-4" />
                Edit
              </Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => rebootMutation.mutate()}
              disabled={rebootMutation.isPending}
            >
              <RefreshCw className="mr-2 h-4 w-4" />
              Reboot
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => reprovisionMutation.mutate()}
              disabled={reprovisionMutation.isPending}
            >
              <RotateCcw className="mr-2 h-4 w-4" />
              Reprovision
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => updateMutation.mutate({ isActive: !device.isActive })}
              disabled={updateMutation.isPending}
            >
              <Power className="mr-2 h-4 w-4" />
              {device.isActive ? "Disable" : "Enable"}
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
