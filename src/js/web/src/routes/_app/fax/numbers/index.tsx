import { createFileRoute, Link } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import {
  AlertCircle,
  CheckCircle2,
  Circle,
  Download,
  Eye,
  Home,
  LayoutGrid,
  List,
  Mail,
  MessageSquare,
  MoreVertical,
  Pencil,
  Plus,
  Printer,
  Search,
  SlidersHorizontal,
  Trash2,
  X,
} from "lucide-react"
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
import { FaxNumberCard } from "@/components/fax/fax-number-card"
import { FaxNumberEditDialog } from "@/components/fax/fax-number-edit-dialog"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { BulkActionBar, createBulkDeleteAction, createExportAction } from "@/components/ui/bulk-action-bar"
import { DataFreshness } from "@/components/ui/data-freshness"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton, SkeletonCard } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { type FaxNumber, useDeleteFaxNumber, useFaxNumbers } from "@/lib/api/hooks/fax"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { useSettingsStore } from "@/lib/settings-store"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/fax/numbers/")({
  validateSearch: (
    search: Record<string, unknown>,
  ): {
    q?: string
    page?: number
    status?: string
    sort?: string
    order?: string
  } => ({
    q: typeof search.q === "string" && search.q ? search.q : undefined,
    page: Number(search.page) > 1 ? Number(search.page) : undefined,
    status: typeof search.status === "string" && search.status ? search.status : undefined,
    sort: typeof search.sort === "string" && search.sort ? search.sort : undefined,
    order:
      typeof search.order === "string" && (search.order === "asc" || search.order === "desc")
        ? search.order
        : undefined,
  }),
  component: FaxNumbersPage,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_STORAGE_KEY = "fax-numbers-page-size"

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

const csvHeaders: CsvHeader<FaxNumber>[] = [
  { label: "Number", accessor: (f) => f.number },
  { label: "Label", accessor: (f) => f.label ?? "" },
  { label: "Status", accessor: (f) => (f.isActive ? "Active" : "Inactive") },
]

const statusOptions: FilterOption[] = [
  { value: "active", label: "Active" },
  { value: "inactive", label: "Inactive" },
]

// -- Column visibility ---------------------------------------------------------

const COLUMN_VISIBILITY_KEY = "fax-numbers-columns"

const TOGGLEABLE_COLUMNS = [
  { key: "status", label: "Status" },
  { key: "label", label: "Label" },
  { key: "emailRoutes", label: "Email Routes" },
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

// -- Helpers ------------------------------------------------------------------

function StatusIndicator({ isActive }: { isActive: boolean }) {
  if (isActive) {
    return (
      <span className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400">
        <CheckCircle2 className="h-3.5 w-3.5" />
        Active
      </span>
    )
  }
  return (
    <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
      <Circle className="h-3.5 w-3.5" />
      Inactive
    </span>
  )
}


// -- Main page ----------------------------------------------------------------

function FaxNumbersPage() {
  useDocumentTitle("Fax Numbers")
  const compactMode = useSettingsStore((s) => s.compactMode)
  const cellClass = compactMode ? "py-1 px-2 text-xs" : ""
  const {
    q: searchParam,
    page: pageParam,
    status: statusParam,
    sort: sortParam,
    order: orderParam,
  } = Route.useSearch()
  const navigate = Route.useNavigate()
  const searchInputRef = useRef<HTMLInputElement>(null)

  // View mode
  const [viewMode, setViewMode] = useState<"table" | "cards">("table")

  // Derive filter state from URL search params
  const search = searchParam ?? ""
  const page = pageParam ?? 1
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
  const { data, isLoading, isError, refetch, dataUpdatedAt, isRefetching } = useFaxNumbers(page, pageSize)

  // Summary stats
  const faxNumberStats = useMemo(() => {
    const items = data?.items ?? []
    let active = 0
    let inactive = 0
    for (const n of items) {
      if (n.isActive) active++
      else inactive++
    }
    return { active, inactive, total: data?.total ?? 0 }
  }, [data?.items, data?.total])
  const deleteFaxNumber = useDeleteFaxNumber()
  const [numberToDelete, setNumberToDelete] = useState<{ id: string; number: string } | null>(null)

  const handleConfirmDelete = () => {
    if (numberToDelete) {
      deleteFaxNumber.mutate(numberToDelete.id, {
        onSuccess: () => {
          setTimeout(() => {
            const searchInput = document.querySelector<HTMLInputElement>('input[placeholder*="Search"]')
            if (searchInput) {
              searchInput.focus()
            }
          }, 0)
        },
      })
      setNumberToDelete(null)
    }
  }

  // Apply client-side search & filters
  const filteredItems = useMemo(() => {
    if (!data?.items) return []
    let items = data.items

    // Search by number or label
    if (search) {
      const q = search.toLowerCase()
      items = items.filter(
        (n) =>
          n.number.toLowerCase().includes(q) ||
          (n.label && n.label.toLowerCase().includes(q)),
      )
    }

    // Status filter
    if (statusFilter.length > 0) {
      items = items.filter((n) => {
        const status = n.isActive ? "active" : "inactive"
        return statusFilter.includes(status)
      })
    }

    // Client-side sorting
    if (sortKey && sortDir) {
      items = [...items].sort((a, b) => {
        let cmp = 0
        switch (sortKey) {
          case "number":
            cmp = a.number.localeCompare(b.number)
            break
          case "label":
            cmp = (a.label ?? "").localeCompare(b.label ?? "")
            break
          case "is_active":
            cmp = Number(a.isActive) - Number(b.isActive)
            break
          case "created_at":
            cmp = (a.createdAt ?? "").localeCompare(b.createdAt ?? "")
            break
          default:
            break
        }
        return sortDir === "desc" ? -cmp : cmp
      })
    }

    return items
  }, [data?.items, search, statusFilter, sortKey, sortDir])

  // Selection helpers
  const allVisibleIds = useMemo(() => filteredItems.map((n) => n.id), [filteredItems])
  const allSelected = filteredItems.length > 0 && filteredItems.every((n) => selectedIds.has(n.id))
  const someSelected = filteredItems.some((n) => selectedIds.has(n.id))

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
        (id) => deleteFaxNumber.mutateAsync(id),
        () => {
          setSelectedIds(new Set())
        },
      ),
      createExportAction<FaxNumber>(
        "fax-numbers-selected",
        csvHeaders,
        (ids) => filteredItems.filter((n) => ids.includes(n.id)),
      ),
    ],
    [filteredItems, deleteFaxNumber],
  )

  // Export all visible
  const handleExportAll = useCallback(() => {
    if (!filteredItems.length) return
    exportToCsv("fax-numbers", csvHeaders, filteredItems)
  }, [filteredItems])

  // Row click handler
  const handleRowClick = useCallback(
    (faxNumberId: string) => {
      navigate({ to: "/fax/numbers/$faxNumberId", params: { faxNumberId } })
    },
    [navigate],
  )

  // Active filter count
  const activeFilterCount = statusFilter.length

  const hasData = filteredItems.length > 0
  const hasAnyNumbers = (data?.items.length ?? 0) > 0
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
          <BreadcrumbLink asChild>
            <Link to="/fax/numbers">Fax</Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          <BreadcrumbPage>Numbers</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Communications"
        title="Fax Numbers"
        description="Manage your fax numbers and configure email delivery routes."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-3">
            <DataFreshness
              dataUpdatedAt={dataUpdatedAt}
              onRefresh={() => refetch()}
              isRefreshing={isRefetching}
            />
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
              <Link to="/fax/numbers/new">
                <Plus className="mr-2 h-4 w-4" /> New Number
              </Link>
            </Button>
            <div className="flex gap-1 rounded-lg border border-border/60 p-0.5">
              <Button
                variant={viewMode === "table" ? "default" : "ghost"}
                size="sm"
                onClick={() => setViewMode("table")}
                className="h-8 px-2"
              >
                <List className="h-4 w-4" />
              </Button>
              <Button
                variant={viewMode === "cards" ? "default" : "ghost"}
                size="sm"
                onClick={() => setViewMode("cards")}
                className="h-8 px-2"
              >
                <LayoutGrid className="h-4 w-4" />
              </Button>
            </div>
          </div>
        }
      />

      {/* Summary stats */}
      <SectionErrorBoundary name="Fax Numbers Summary">
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
              <span className="ml-0.5 font-semibold text-foreground">{faxNumberStats.total}</span>
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
              Active
              <span className="ml-0.5 font-semibold">{faxNumberStats.active}</span>
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-zinc-400/30 bg-zinc-400/10 px-3 py-1 text-xs font-medium text-zinc-600 dark:text-zinc-400">
              <span className="h-1.5 w-1.5 rounded-full bg-zinc-400" />
              Inactive
              <span className="ml-0.5 font-semibold">{faxNumberStats.inactive}</span>
            </span>
          </>
        )}
      </div>
      </SectionErrorBoundary>

      {/* Search & filters */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              ref={searchInputRef}
              placeholder="Search by number or label..."
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
        <SectionErrorBoundary name="Fax Numbers Table">
        {isLoading ? (
          viewMode === "table" ? (
            <div className="space-y-3">
              <div className="h-5" />
              <div className="rounded-md border border-border/60 bg-card/80 p-8">
                <div className="animate-pulse space-y-4">
                  {Array.from({ length: 5 }).map((_, i) => (
                    // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
                    <div key={`skel-row-${i}`} className="h-8 rounded bg-muted/40" />
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {Array.from({ length: 6 }).map((_, index) => (
                // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
                <SkeletonCard key={`fax-num-skeleton-${index}`} />
              ))}
            </div>
          )
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load fax numbers"
            description="Something went wrong while fetching your fax numbers. Please try again."
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Try again
              </Button>
            }
          />
        ) : !hasAnyNumbers && !search ? (
          <EmptyState
            icon={Printer}
            title="No fax numbers yet"
            description="Add your first fax number to start sending and receiving faxes. You can configure email delivery routes after adding a number."
            action={
              <Button size="sm" asChild>
                <Link to="/fax/numbers/new">
                  <Plus className="mr-2 h-4 w-4" /> New Number
                </Link>
              </Button>
            }
          />
        ) : !hasData ? (
          <EmptyState
            icon={Printer}
            variant="no-results"
            title="No results found"
            description="No fax numbers match your current search or filters. Try adjusting your criteria."
            action={
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setSearchInput("")
                  navigate({
                    search: {
                      q: undefined,
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
        ) : viewMode === "table" ? (
          <div className="space-y-3">
            {/* Result count & pagination info */}
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">
                {data?.total ?? filteredItems.length} fax number{(data?.total ?? filteredItems.length) === 1 ? "" : "s"}
                {activeFilterCount > 0 && " (filtered)"}
              </p>
              {totalPages > 1 && (
                <p className="text-xs text-muted-foreground">
                  Page {page} of {totalPages}
                </p>
              )}
            </div>

            <div className="sr-only" aria-live="polite" aria-atomic="true">
              {!isLoading && `Showing ${filteredItems.length} of ${data?.total ?? 0} fax numbers, page ${page}`}
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
              <Table aria-label="Fax numbers" aria-busy={isLoading || isRefetching}>
                <TableHeader className="sticky top-0 z-10 bg-background">
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all fax numbers"
                      />
                    </TableHead>
                    <SortableHeader
                      label="Number"
                      sortKey="number"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    {isColumnVisible("label") && (
                      <SortableHeader
                        label="Label"
                        sortKey="label"
                        currentSort={sortKey}
                        currentDirection={sortDir}
                        onSort={handleSort}
                      />
                    )}
                    {isColumnVisible("status") && (
                      <SortableHeader
                        label="Status"
                        sortKey="is_active"
                        currentSort={sortKey}
                        currentDirection={sortDir}
                        onSort={handleSort}
                      />
                    )}
                    {isColumnVisible("emailRoutes") && (
                      <TableHead>Email Routes</TableHead>
                    )}
                    {isColumnVisible("created") && (
                      <SortableHeader
                        label="Created"
                        sortKey="created_at"
                        currentSort={sortKey}
                        currentDirection={sortDir}
                        onSort={handleSort}
                      />
                    )}
                    <TableHead className="w-16 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredItems.map((faxNumber, index) => (
                    <FaxNumberRow
                      key={faxNumber.id}
                      faxNumber={faxNumber}
                      index={index}
                      selected={selectedIds.has(faxNumber.id)}
                      onToggle={() => toggleOne(faxNumber.id)}
                      onRowClick={() => handleRowClick(faxNumber.id)}
                      onDelete={() => setNumberToDelete({ id: faxNumber.id, number: faxNumber.number })}
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
        ) : (
          <div className="space-y-3">
            <p className="text-xs text-muted-foreground">
              {data?.total ?? filteredItems.length} fax number{(data?.total ?? filteredItems.length) === 1 ? "" : "s"}
              {activeFilterCount > 0 && " (filtered)"}
            </p>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {filteredItems.map((faxNumber) => (
                <FaxNumberCard key={faxNumber.id} faxNumber={faxNumber} />
              ))}
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

      <AlertDialog open={!!numberToDelete} onOpenChange={(open) => !open && setNumberToDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete fax number?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete <span className="font-medium text-foreground">{numberToDelete?.number}</span>. This action cannot be undone.
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

// -- Table row ----------------------------------------------------------------

function FaxNumberRow({
  faxNumber,
  index,
  selected,
  onToggle,
  onRowClick,
  onDelete,
  cellClass,
  isColumnVisible,
}: {
  faxNumber: FaxNumber
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
  onDelete: () => void
  cellClass: string
  isColumnVisible: (col: string) => boolean
}) {
  const [editOpen, setEditOpen] = useState(false)

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
          aria-label={`Select ${faxNumber.number}`}
        />
      </TableCell>
      <TableCell className={cellClass}>
        <Link
          to="/fax/numbers/$faxNumberId"
          params={{ faxNumberId: faxNumber.id }}
          className="group flex flex-col gap-0.5"
          onClick={(e) => e.stopPropagation()}
        >
          <span className="font-mono font-medium group-hover:underline">
            {faxNumber.number}
          </span>
        </Link>
      </TableCell>
      {isColumnVisible("label") && (
        <TableCell className={cellClass}>
          <span className="text-muted-foreground">{faxNumber.label ?? "--"}</span>
        </TableCell>
      )}
      {isColumnVisible("status") && (
        <TableCell className={cellClass}>
          <StatusIndicator isActive={faxNumber.isActive} />
        </TableCell>
      )}
      {isColumnVisible("emailRoutes") && (
        <TableCell className={cellClass}>
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <Mail className="h-3.5 w-3.5" />
            <span>Configured</span>
          </div>
        </TableCell>
      )}
      {isColumnVisible("created") && (
        <TableCell className={cellClass}>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="text-xs text-muted-foreground">
                {formatRelativeTimeShort(faxNumber.createdAt)}
              </span>
            </TooltipTrigger>
            <TooltipContent>{formatDateTime(faxNumber.createdAt)}</TooltipContent>
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
              <span className="sr-only">Actions for {faxNumber.number}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link to="/fax/numbers/$faxNumberId" params={{ faxNumberId: faxNumber.id }}>
                <Eye className="mr-2 h-4 w-4" />
                View details
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => setEditOpen(true)}>
              <Pencil className="mr-2 h-4 w-4" />
              Edit
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <Link to="/fax/messages" search={{ number: faxNumber.number }}>
                <MessageSquare className="mr-2 h-4 w-4" />
                Messages
              </Link>
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
        <FaxNumberEditDialog faxNumber={faxNumber} open={editOpen} onOpenChange={setEditOpen} />
      </TableCell>
    </TableRow>
  )
}
