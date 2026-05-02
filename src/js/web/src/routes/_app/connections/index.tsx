import { createFileRoute, Link } from "@tanstack/react-router"
import {
  AlertCircle,
  Cable,
  CheckCircle2,
  Circle,
  Download,
  Eye,
  Home,
  Loader2,
  MoreVertical,
  Pencil,
  Plus,
  Search,
  SlidersHorizontal,
  Trash2,
  X,
  XCircle,
  Zap,
} from "lucide-react"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
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
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { BulkActionBar, createBulkDeleteAction, createBulkToggleActions, createExportAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { DataFreshness } from "@/components/ui/data-freshness"
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
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton, SkeletonCard } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { type ConnectionList, useConnections, useDeleteConnection, useTestAnyConnection, useUpdateAnyConnection } from "@/lib/api/hooks/connections"
import { type CsvHeader, exportToCsv } from "@/lib/csv-export"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { useSettingsStore } from "@/lib/settings-store"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/connections/")({
  validateSearch: (
    search: Record<string, unknown>,
  ): {
    q?: string
    page?: number
    type?: string
    status?: string
    sort?: string
    order?: string
  } => ({
    q: typeof search.q === "string" && search.q ? search.q : undefined,
    page: Number(search.page) > 1 ? Number(search.page) : undefined,
    type: typeof search.type === "string" && search.type ? search.type : undefined,
    status: typeof search.status === "string" && search.status ? search.status : undefined,
    sort: typeof search.sort === "string" && search.sort ? search.sort : undefined,
    order: typeof search.order === "string" && (search.order === "asc" || search.order === "desc") ? search.order : undefined,
  }),
  component: ConnectionsPage,
})

// ── Constants ────────────────────────────────────────────────────────────

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_STORAGE_KEY = "connections-page-size"
const AUTO_REFRESH_STORAGE_KEY = "connections-auto-refresh"
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

const typeLabels: Record<string, string> = {
  pbx: "PBX",
  helpdesk: "Helpdesk",
  carrier: "Carrier",
  network: "Network",
  other: "Other",
}

const typeBadgeVariant: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
  pbx: "default",
  helpdesk: "secondary",
  carrier: "outline",
  network: "secondary",
  other: "outline",
}

const connectionTypeOptions: FilterOption[] = [
  { value: "pbx", label: "PBX" },
  { value: "helpdesk", label: "Helpdesk" },
  { value: "carrier", label: "Carrier" },
  { value: "network", label: "Network" },
  { value: "other", label: "Other" },
]

const statusOptions: FilterOption[] = [
  { value: "connected", label: "Connected" },
  { value: "disconnected", label: "Disconnected" },
  { value: "error", label: "Error" },
]

const csvHeaders: CsvHeader<ConnectionList>[] = [
  { label: "Name", accessor: (c) => c.name },
  { label: "Provider", accessor: (c) => c.provider },
  { label: "Status", accessor: (c) => c.status },
  { label: "Type", accessor: (c) => typeLabels[c.connectionType] ?? c.connectionType },
]

// ── Column visibility ────────────────────────────────────────────────────

const COLUMN_VISIBILITY_KEY = "connections-columns"

const TOGGLEABLE_COLUMNS = [
  { key: "type", label: "Type" },
  { key: "status", label: "Status" },
  { key: "host", label: "Host" },
  { key: "lastSync", label: "Last Tested" },
  { key: "created", label: "Created" },
] as const

type ColumnVisibility = Record<string, boolean>

function loadColumnVisibility(): ColumnVisibility {
  try {
    return JSON.parse(localStorage.getItem(COLUMN_VISIBILITY_KEY) ?? "{}")
  } catch {
    return {}
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────

function StatusIndicator({ status }: { status: string }) {
  switch (status) {
    case "connected":
      return (
        <span className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400">
          <CheckCircle2 className="h-3.5 w-3.5" />
          Connected
        </span>
      )
    case "disconnected":
      return (
        <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <XCircle className="h-3.5 w-3.5" />
          Disconnected
        </span>
      )
    case "error":
      return (
        <span className="flex items-center gap-1.5 text-xs text-destructive">
          <AlertCircle className="h-3.5 w-3.5" />
          Error
        </span>
      )
    default:
      return (
        <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Circle className="h-3.5 w-3.5" />
          Unknown
        </span>
      )
  }
}

// ── Main page ────────────────────────────────────────────────────────────

function ConnectionsPage() {
  useDocumentTitle("Connections")
  const compactMode = useSettingsStore((s) => s.compactMode)
  const cellClass = compactMode ? "py-1 px-2 text-xs" : ""
  const { q: searchParam, page: pageParam, type: typeParam, status: statusParam, sort: sortParam, order: orderParam } = Route.useSearch()
  const navigate = Route.useNavigate()
  const searchInputRef = useRef<HTMLInputElement>(null)

  // Column visibility
  const [columnVisibility, setColumnVisibility] = useState<ColumnVisibility>(loadColumnVisibility)
  const isColumnVisible = useCallback((col: string) => columnVisibility[col] !== false, [columnVisibility])
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

  // Derive filter state from URL search params
  const search = searchParam ?? ""
  const page = pageParam ?? 1
  const typeFilter = useMemo(() => (typeParam ? typeParam.split(",").filter(Boolean) : []), [typeParam])
  const statusFilter = useMemo(() => (statusParam ? statusParam.split(",").filter(Boolean) : []), [statusParam])
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
  const { data, isLoading, isError, refetch, dataUpdatedAt, isRefetching } = useConnections({
    page,
    pageSize,
    search: debouncedSearch || undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
    refetchInterval: autoRefresh ? AUTO_REFRESH_INTERVAL : false,
  })
  const deleteConnection = useDeleteConnection()
  const updateAnyConnection = useUpdateAnyConnection()
  const testConnection = useTestAnyConnection()
  const [itemToDelete, setItemToDelete] = useState<{ id: string; name: string } | null>(null)

  const handleConfirmDelete = () => {
    if (itemToDelete) {
      deleteConnection.mutate(itemToDelete.id, {
        onSuccess: () => {
          // The deleted row is gone, so restore focus to the search input
          setTimeout(() => {
            const searchInput = document.querySelector<HTMLInputElement>('input[placeholder*="Search"]')
            if (searchInput) {
              searchInput.focus()
            }
          }, 0)
        },
      })
      setItemToDelete(null)
    }
  }

  // Row click handler
  const handleRowClick = useCallback(
    (connectionId: string) => {
      navigate({ to: "/connections/$connectionId", params: { connectionId } })
    },
    [navigate],
  )

  // Apply client-side type & status filters
  const filteredItems = useMemo(() => {
    if (!data?.items) return []
    return data.items.filter((conn) => {
      if (typeFilter.length > 0 && !typeFilter.includes(conn.connectionType)) return false
      if (statusFilter.length > 0 && !statusFilter.includes(conn.status)) return false
      return true
    })
  }, [data?.items, typeFilter, statusFilter])

  // Export all visible
  const handleExportAll = useCallback(() => {
    if (!filteredItems.length) return
    exportToCsv("connections", csvHeaders, filteredItems)
  }, [filteredItems])

  // Selection helpers
  const allVisibleIds = useMemo(() => filteredItems.map((c) => c.id), [filteredItems])
  const allSelected = filteredItems.length > 0 && filteredItems.every((c) => selectedIds.has(c.id))
  const someSelected = filteredItems.some((c) => selectedIds.has(c.id))

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
  const [bulkEnableAction, bulkDisableAction] = useMemo(
    () =>
      createBulkToggleActions(
        (id, enabled) => updateAnyConnection.mutateAsync({ connectionId: id, payload: { isEnabled: enabled } }).then(() => {}),
        () => {},
        { entityName: "connection" },
      ),
    [updateAnyConnection],
  )

  const bulkActions = useMemo(
    () => [
      bulkEnableAction,
      bulkDisableAction,
      createBulkDeleteAction(
        (id) => deleteConnection.mutateAsync(id),
        () => {
          setSelectedIds(new Set())
        },
      ),
      createExportAction<ConnectionList>("connections-selected", csvHeaders, (ids) => filteredItems.filter((c) => ids.includes(c.id))),
    ],
    [bulkEnableAction, bulkDisableAction, filteredItems, deleteConnection],
  )

  // Active filter count for display
  const activeFilterCount = typeFilter.length + statusFilter.length

  const hasData = filteredItems.length > 0
  const hasAnyConnections = (data?.items.length ?? 0) > 0
  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / pageSize))

  // Connection health summary
  const healthStats = useMemo(() => {
    const items = data?.items ?? []
    let connected = 0
    let disconnected = 0
    let disabled = 0
    for (const c of items) {
      if (!c.isEnabled) disabled++
      else if (c.status === "connected") connected++
      else disconnected++
    }
    return { total: data?.total ?? items.length, connected, disconnected, disabled }
  }, [data?.items, data?.total])

  // Keyboard shortcuts: "/" to focus search, "N" opens create page, ArrowLeft/ArrowRight for pagination
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return
      if (e.key === "/" && !e.ctrlKey && !e.metaKey) {
        e.preventDefault()
        searchInputRef.current?.focus()
      }
      if (e.key === "n" && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault()
        navigate({ to: "/connections/new" })
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
  }, [navigate, page, totalPages])

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
          <BreadcrumbPage>Connections</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Connections"
        description="Manage external data source integrations (PBX, helpdesk, carriers, and more)."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-2">
            <DataFreshness dataUpdatedAt={dataUpdatedAt} onRefresh={() => refetch()} isRefreshing={isRefetching} />
            <Button variant={autoRefresh ? "default" : "outline"} size="sm" onClick={toggleAutoRefresh}>
              {autoRefresh && <span className="mr-2 h-2 w-2 animate-pulse rounded-full bg-emerald-500" />}
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
                  <DropdownMenuCheckboxItem key={col.key} checked={isColumnVisible(col.key)} onCheckedChange={() => toggleColumn(col.key)}>
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
              <Link to="/connections/new">
                <Plus className="mr-2 h-4 w-4" /> Add connection
                <kbd className="ml-1.5 hidden rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground sm:inline">N</kbd>
              </Link>
            </Button>
          </div>
        }
      />

      {/* Summary distribution pills */}
      <SectionErrorBoundary name="Connection Statistics">
        <div className="flex flex-wrap items-center gap-2">
          {isLoading ? (
            <>
              <Skeleton className="h-7 w-24 rounded-full" />
              <Skeleton className="h-7 w-28 rounded-full" />
              <Skeleton className="h-7 w-32 rounded-full" />
              <Skeleton className="h-7 w-24 rounded-full" />
            </>
          ) : (
            <>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-muted/50 px-3 py-1 text-xs font-medium text-muted-foreground">
                Total
                <span className="ml-0.5 font-semibold text-foreground">{healthStats.total}</span>
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-400">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                Connected
                <span className="ml-0.5 font-semibold">{healthStats.connected}</span>
              </span>
              {healthStats.disconnected > 0 && (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-red-500/30 bg-red-500/10 px-3 py-1 text-xs font-medium text-red-700 dark:text-red-400">
                  <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
                  Disconnected
                  <span className="ml-0.5 font-semibold">{healthStats.disconnected}</span>
                </span>
              )}
              {healthStats.disabled > 0 && (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-zinc-400/30 bg-zinc-400/10 px-3 py-1 text-xs font-medium text-zinc-600 dark:text-zinc-400">
                  <span className="h-1.5 w-1.5 rounded-full bg-zinc-400" />
                  Disabled
                  <span className="ml-0.5 font-semibold">{healthStats.disabled}</span>
                </span>
              )}
            </>
          )}
        </div>
      </SectionErrorBoundary>

      {/* Search & filters */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input ref={searchInputRef} placeholder="Search by name or provider..." value={searchInput} onChange={(e) => setSearchInput(e.target.value)} className="pl-9 pr-8" />
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
              <kbd className="pointer-events-none absolute right-8 top-1/2 -translate-y-1/2 hidden rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground sm:inline">
                /
              </kbd>
            )}
          </div>
          <FilterDropdown
            label="Type"
            options={connectionTypeOptions}
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
          {activeFilterCount > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="text-xs text-muted-foreground"
              onClick={() => {
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
        <SectionErrorBoundary name="Connections Table">
          {isLoading ? (
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <SkeletonCard key={i} />
              ))}
            </div>
          ) : isError ? (
            <EmptyState
              icon={AlertCircle}
              title="Unable to load connections"
              description="Something went wrong while fetching your connections. Please try again."
              action={
                <Button variant="outline" size="sm" onClick={() => refetch()}>
                  Try again
                </Button>
              }
            />
          ) : !hasAnyConnections && !search ? (
            <EmptyState
              icon={Cable}
              title="No connections yet"
              description="Add your first connection to integrate with an external data source."
              action={
                <Button size="sm" asChild>
                  <Link to="/connections/new">
                    <Plus className="mr-2 h-4 w-4" /> Add connection
                  </Link>
                </Button>
              }
            />
          ) : !hasData ? (
            <EmptyState
              icon={Cable}
              variant="no-results"
              title="No results found"
              description="No connections match your current filters. Try adjusting your search or filters."
              action={
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setSearchInput("")
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
                  {data?.total ?? filteredItems.length} connection{(data?.total ?? filteredItems.length) === 1 ? "" : "s"}
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
                <Table aria-label="Connections" aria-busy={isLoading || isRefetching}>
                  <TableHeader className="sticky top-0 z-10 bg-background">
                    <TableRow>
                      <TableHead className="w-10">
                        <Checkbox checked={allSelected} indeterminate={someSelected && !allSelected} onChange={toggleAll} aria-label="Select all connections" />
                      </TableHead>
                      <SortableHeader label="Name" sortKey="name" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />
                      {isColumnVisible("type") && (
                        <SortableHeader
                          label="Type"
                          sortKey="connection_type"
                          currentSort={sortKey}
                          currentDirection={sortDir}
                          onSort={handleSort}
                          className="hidden md:table-cell"
                        />
                      )}
                      {isColumnVisible("status") && <SortableHeader label="Status" sortKey="status" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />}
                      {isColumnVisible("host") && <TableHead className="hidden md:table-cell">Host</TableHead>}
                      {isColumnVisible("lastSync") && (
                        <SortableHeader
                          label="Last Tested"
                          sortKey="last_health_check"
                          currentSort={sortKey}
                          currentDirection={sortDir}
                          onSort={handleSort}
                          className="hidden md:table-cell"
                        />
                      )}
                      {isColumnVisible("created") && (
                        <SortableHeader
                          label="Created"
                          sortKey="created_at"
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
                    {filteredItems.map((conn, index) => (
                      <ConnectionRow
                        key={conn.id}
                        conn={conn}
                        index={index}
                        selected={selectedIds.has(conn.id)}
                        onToggle={() => toggleOne(conn.id)}
                        onRowClick={() => handleRowClick(conn.id)}
                        onDelete={() => setItemToDelete({ id: conn.id, name: conn.name })}
                        onTest={() => testConnection.mutate(conn.id)}
                        isTestPending={testConnection.isPending && testConnection.variables === conn.id}
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
            </div>
          )}
        </SectionErrorBoundary>
      </PageSection>

      {/* Bulk action bar */}
      <BulkActionBar selectedCount={selectedIds.size} selectedIds={Array.from(selectedIds)} onClearSelection={() => setSelectedIds(new Set())} actions={bulkActions} />

      <AlertDialog open={!!itemToDelete} onOpenChange={(open) => !open && setItemToDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete connection?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete <span className="font-medium text-foreground">{itemToDelete?.name}</span>. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleConfirmDelete} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </PageContainer>
  )
}

// ── Table row ────────────────────────────────────────────────────────────

function ConnectionRow({
  conn,
  index,
  selected,
  onToggle,
  onRowClick,
  onDelete,
  onTest,
  isTestPending,
  cellClass,
  isColumnVisible,
}: {
  conn: ConnectionList
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
  onDelete: () => void
  onTest: () => void
  isTestPending: boolean
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
          aria-label={`Select ${conn.name}`}
        />
      </TableCell>
      <TableCell className={cellClass}>
        <Link to="/connections/$connectionId" params={{ connectionId: conn.id }} className="group flex flex-col gap-0.5" onClick={(e) => e.stopPropagation()}>
          <span className="font-medium group-hover:underline">{conn.name}</span>
          <span className="text-xs text-muted-foreground">{conn.provider}</span>
        </Link>
      </TableCell>
      {isColumnVisible("type") && (
        <TableCell className={cn("hidden md:table-cell", cellClass)}>
          <Badge variant={typeBadgeVariant[conn.connectionType] ?? "outline"}>{typeLabels[conn.connectionType] ?? conn.connectionType}</Badge>
        </TableCell>
      )}
      {isColumnVisible("status") && (
        <TableCell className={cellClass}>
          <div className="flex items-center gap-2">
            <StatusIndicator status={conn.status} />
            {!conn.isEnabled && (
              <Badge variant="outline" className="border-muted-foreground/30 text-muted-foreground text-[10px]">
                Disabled
              </Badge>
            )}
          </div>
        </TableCell>
      )}
      {isColumnVisible("host") && (
        <TableCell className={cn("hidden md:table-cell", cellClass)}>
          {conn.host ? (
            <span className="font-mono text-xs text-muted-foreground">
              {conn.host}
              {conn.port ? `:${conn.port}` : ""}
            </span>
          ) : (
            <span className="text-xs text-muted-foreground">--</span>
          )}
        </TableCell>
      )}
      {isColumnVisible("lastSync") && (
        <TableCell className={cn("hidden md:table-cell", cellClass)}>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="cursor-default text-xs text-muted-foreground">{formatRelativeTimeShort(conn.lastHealthCheck)}</span>
            </TooltipTrigger>
            <TooltipContent>{formatDateTime(conn.lastHealthCheck)}</TooltipContent>
          </Tooltip>
        </TableCell>
      )}
      {isColumnVisible("created") && (
        <TableCell className={cn("hidden md:table-cell", cellClass)}>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="cursor-default text-xs text-muted-foreground">{formatRelativeTimeShort(conn.createdAt)}</span>
            </TooltipTrigger>
            <TooltipContent>{formatDateTime(conn.createdAt)}</TooltipContent>
          </Tooltip>
        </TableCell>
      )}
      <TableCell className={cn("text-right", cellClass)}>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" className="h-8 w-8 p-0" data-slot="dropdown" onClick={(e) => e.stopPropagation()}>
              <MoreVertical className="h-4 w-4" />
              <span className="sr-only">Actions for {conn.name}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link to="/connections/$connectionId" params={{ connectionId: conn.id }}>
                <Eye className="mr-2 h-4 w-4" />
                View details
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link to="/connections/$connectionId/edit" params={{ connectionId: conn.id }}>
                <Pencil className="mr-2 h-4 w-4" />
                Edit
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem onClick={onTest} disabled={isTestPending}>
              {isTestPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Zap className="mr-2 h-4 w-4" />}
              Test connection
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={onDelete} className="text-destructive focus:text-destructive">
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  )
}
