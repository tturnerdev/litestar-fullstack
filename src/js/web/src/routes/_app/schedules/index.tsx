import { createFileRoute, Link } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useState } from "react"
import {
  AlertCircle,
  Calendar,
  CheckCircle2,
  Clock,
  Copy,
  Download,
  Eye,
  Globe,
  Home,
  Loader2,
  MoreVertical,
  Pencil,
  Plus,
  Search,
  SlidersHorizontal,
  Star,
  Trash2,
  X,
  XCircle,
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
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton, SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  useSchedules,
  useDeleteSchedule,
  useCheckSchedule,
  type Schedule,
} from "@/lib/api/hooks/schedules"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime } from "@/lib/date-utils"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { useSettingsStore } from "@/lib/settings-store"
import { cn } from "@/lib/utils"
import { toast } from "sonner"

export const Route = createFileRoute("/_app/schedules/")({
  validateSearch: (
    search: Record<string, unknown>,
  ): {
    q?: string
    page?: number
    sort?: string
    order?: string
  } => ({
    q: typeof search.q === "string" && search.q ? search.q : undefined,
    page: Number(search.page) > 1 ? Number(search.page) : undefined,
    sort: typeof search.sort === "string" && search.sort ? search.sort : undefined,
    order:
      typeof search.order === "string" && (search.order === "asc" || search.order === "desc")
        ? search.order
        : undefined,
  }),
  component: SchedulesPage,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_STORAGE_KEY = "schedules-page-size"

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

const scheduleTypeLabels: Record<string, string> = {
  business_hours: "Business Hours",
  holiday: "Holiday",
  custom: "Custom",
}

const scheduleTypeVariant: Record<string, "default" | "secondary" | "outline"> = {
  business_hours: "default",
  holiday: "secondary",
  custom: "outline",
}

const scheduleTypeIcons: Record<string, typeof Clock> = {
  business_hours: Clock,
  holiday: Calendar,
  custom: SlidersHorizontal,
}

const csvHeaders: CsvHeader<Schedule>[] = [
  { label: "Name", accessor: (s) => s.name },
  { label: "Type", accessor: (s) => scheduleTypeLabels[s.scheduleType] ?? s.scheduleType },
  { label: "Timezone", accessor: (s) => s.timezone },
  { label: "Default", accessor: (s) => (s.isDefault ? "Yes" : "No") },
  { label: "Created", accessor: (s) => (s.createdAt ? formatDateTime(s.createdAt) : "") },
  { label: "Updated", accessor: (s) => (s.updatedAt ? formatDateTime(s.updatedAt) : "") },
]

// -- Column visibility ---------------------------------------------------------

const COLUMN_VISIBILITY_KEY = "schedules-columns"

const TOGGLEABLE_COLUMNS = [
  { key: "type", label: "Type" },
  { key: "timezone", label: "Timezone" },
  { key: "entries", label: "Entries" },
  { key: "status", label: "Status" },
] as const

type ColumnVisibility = Record<string, boolean>

function loadColumnVisibility(): ColumnVisibility {
  try {
    return JSON.parse(localStorage.getItem(COLUMN_VISIBILITY_KEY) ?? "{}")
  } catch {
    return {}
  }
}

// -- Status badge (per-row) ---------------------------------------------------

function ScheduleStatusBadge({ scheduleId }: { scheduleId: string }) {
  const { data, isLoading } = useCheckSchedule(scheduleId)

  if (isLoading) {
    return (
      <Badge variant="outline" className="gap-1 text-muted-foreground">
        <Loader2 className="h-3 w-3 animate-spin" />
        Checking
      </Badge>
    )
  }

  if (!data) {
    return (
      <Badge variant="outline" className="gap-1 text-muted-foreground">
        --
      </Badge>
    )
  }

  if (data.isOpen) {
    return (
      <Badge className="gap-1 bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">
        <CheckCircle2 className="h-3 w-3" />
        Open
      </Badge>
    )
  }

  return (
    <Badge variant="outline" className="gap-1">
      <XCircle className="h-3 w-3" />
      Closed
    </Badge>
  )
}

// -- Main page ----------------------------------------------------------------

function SchedulesPage() {
  useDocumentTitle("Schedules")
  const compactMode = useSettingsStore((s) => s.compactMode)
  const cellClass = compactMode ? "py-1 px-2 text-xs" : ""

  const {
    q: searchParam,
    page: pageParam,
    sort: sortParam,
    order: orderParam,
  } = Route.useSearch()
  const navigate = Route.useNavigate()

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

  const { data, isLoading, isRefetching, isError, refetch } = useSchedules({
    page,
    pageSize,
    search: debouncedSearch || undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
  })

  const deleteSchedule = useDeleteSchedule()

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  const schedules = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / pageSize))

  // filteredItems (no client-side filters currently, but keeps export consistent)
  const filteredItems = useMemo(() => schedules, [schedules])

  // Schedule summary stats (computed from fetched items)
  const scheduleStats = useMemo(() => {
    let active = 0
    let inactive = 0
    for (const s of schedules) {
      const hasEntries = s.entries && s.entries.length > 0
      if (hasEntries) active++
      else inactive++
    }
    return { total, active, inactive }
  }, [schedules, total])

  // Selection helpers
  const allVisibleIds = useMemo(() => filteredItems.map((s) => s.id), [filteredItems])
  const allSelected = filteredItems.length > 0 && filteredItems.every((s) => selectedIds.has(s.id))
  const someSelected = filteredItems.some((s) => selectedIds.has(s.id))

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

  const handleRowClick = useCallback(
    (scheduleId: string) => {
      navigate({ to: "/schedules/$scheduleId", params: { scheduleId } })
    },
    [navigate],
  )

  // Bulk actions
  const bulkActions = useMemo(
    () => [
      createBulkDeleteAction(
        (id) => deleteSchedule.mutateAsync(id),
        () => refetch(),
        { label: "Delete Selected" },
      ),
      createExportAction<Schedule>(
        "schedules-selected",
        csvHeaders,
        (ids) => filteredItems.filter((s) => ids.includes(s.id)),
      ),
    ],
    [deleteSchedule, refetch, filteredItems],
  )

  // Export all visible
  const handleExportAll = useCallback(() => {
    if (!filteredItems.length) return
    exportToCsv("schedules", csvHeaders, filteredItems)
  }, [filteredItems])

  const hasData = filteredItems.length > 0
  const hasActiveFilters = search !== ""

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
          <BreadcrumbPage>Schedules</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Workspace"
        title="Schedules"
        description="Manage business hours, holiday schedules, and custom time windows."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-2">
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
              <Link to="/schedules/new">
                <Plus className="mr-2 h-4 w-4" /> New schedule
              </Link>
            </Button>
          </div>
        }
      />

      {/* Summary stats */}
      <SectionErrorBoundary name="Schedule Status Summary">
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
              <span className="ml-0.5 font-semibold text-foreground">{scheduleStats.total}</span>
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
              Active
              <span className="ml-0.5 font-semibold">{scheduleStats.active}</span>
            </span>
            {scheduleStats.inactive > 0 && (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-zinc-400/30 bg-zinc-400/10 px-3 py-1 text-xs font-medium text-zinc-600 dark:text-zinc-400">
                <span className="h-1.5 w-1.5 rounded-full bg-zinc-400" />
                Inactive
                <span className="ml-0.5 font-semibold">{scheduleStats.inactive}</span>
              </span>
            )}
          </>
        )}
      </div>
      </SectionErrorBoundary>

      {/* Search */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search schedules..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              className="pl-9 pr-8"
            />
            {searchInput && (
              <button
                type="button"
                onClick={() => setSearchInput("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
              >
                <X className="h-3.5 w-3.5" />
                <span className="sr-only">Clear search</span>
              </button>
            )}
          </div>
        </div>
      </PageSection>

      {/* Content */}
      <PageSection delay={0.1}>
        <SectionErrorBoundary name="Schedules Table">
        {isLoading ? (
          <SkeletonTable rows={6} />
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load schedules"
            description="Something went wrong while fetching your schedules. Please try again."
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Try again
              </Button>
            }
          />
        ) : schedules.length === 0 && !hasActiveFilters ? (
          <EmptyState
            icon={Calendar}
            title="No schedules yet"
            description="Create your first schedule to define business hours, holidays, or custom operating windows."
            action={
              <Button size="sm" asChild>
                <Link to="/schedules/new">
                  <Plus className="mr-2 h-4 w-4" /> New schedule
                </Link>
              </Button>
            }
          />
        ) : schedules.length === 0 ? (
          <EmptyState
            icon={Calendar}
            variant="no-results"
            title="No results found"
            description="No schedules match your current search. Try adjusting your search terms."
            action={
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setSearchInput("")
                  navigate({
                    search: {
                      q: undefined,
                      sort: undefined,
                      order: undefined,
                      page: undefined,
                    },
                  })
                }}
              >
                Clear search
              </Button>
            }
          />
        ) : (
          <div className="space-y-3">
            {/* Result count & pagination info */}
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">
                {total} schedule{total === 1 ? "" : "s"}
                {hasActiveFilters && " (filtered)"}
              </p>
              {totalPages > 1 && (
                <p className="text-xs text-muted-foreground">
                  Page {page} of {totalPages}
                </p>
              )}
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
              <Table aria-label="Schedules" aria-busy={isLoading || isRefetching}>
                <TableHeader className="sticky top-0 z-10 bg-background">
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all schedules"
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
                      <TableHead className="hidden md:table-cell">Type</TableHead>
                    )}
                    {isColumnVisible("timezone") && (
                      <SortableHeader
                        label="Timezone"
                        sortKey="timezone"
                        currentSort={sortKey}
                        currentDirection={sortDir}
                        onSort={handleSort}
                        className="hidden md:table-cell"
                      />
                    )}
                    {isColumnVisible("entries") && (
                      <TableHead className="hidden lg:table-cell">Entries</TableHead>
                    )}
                    {isColumnVisible("status") && (
                      <TableHead>Status</TableHead>
                    )}
                    <TableHead className="w-16 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredItems.map((schedule, index) => (
                    <ScheduleRow
                      key={schedule.id}
                      schedule={schedule}
                      index={index}
                      selected={selectedIds.has(schedule.id)}
                      onToggle={() => toggleOne(schedule.id)}
                      onRowClick={() => handleRowClick(schedule.id)}
                      cellClass={cellClass}
                      isColumnVisible={isColumnVisible}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className="sr-only" aria-live="polite" aria-atomic="true">
              {!isLoading && `Showing ${filteredItems.length} of ${total} results, page ${page}`}
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

function ScheduleRow({
  schedule,
  index,
  selected,
  onToggle,
  onRowClick,
  cellClass,
  isColumnVisible,
}: {
  schedule: Schedule
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
  cellClass: string
  isColumnVisible: (col: string) => boolean
}) {
  const deleteSchedule = useDeleteSchedule()
  const [itemToDelete, setItemToDelete] = useState<{ id: string; name: string } | null>(null)

  const handleConfirmDelete = () => {
    if (itemToDelete) {
      deleteSchedule.mutate(itemToDelete.id, {
        onSuccess: () => {
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

  return (
    <TableRow
      data-state={selected ? "selected" : undefined}
      className={`cursor-pointer hover:bg-muted/50 transition-colors ${index % 2 === 1 ? "bg-muted/20" : ""}`}
      onClick={(e) => {
        const target = e.target as HTMLElement
        if (target.closest("[role=checkbox]") || target.closest("a") || target.closest("button") || target.closest("[data-slot=dropdown]")) return
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
          aria-label={`Select ${schedule.name}`}
        />
      </TableCell>
      <TableCell className={cellClass}>
        <Link
          to="/schedules/$scheduleId"
          params={{ scheduleId: schedule.id }}
          className="group flex items-center gap-2"
          onClick={(e) => e.stopPropagation()}
        >
          {(() => {
            const TypeIcon = scheduleTypeIcons[schedule.scheduleType] ?? Clock
            return <TypeIcon className="h-4 w-4 shrink-0 text-muted-foreground" />
          })()}
          <span className="font-medium group-hover:underline">{schedule.name}</span>
          {schedule.isDefault && (
            <Badge className="ml-1 gap-1 bg-amber-100 text-amber-700 hover:bg-amber-100 dark:bg-amber-900/30 dark:text-amber-400" variant="secondary">
              <Star className="h-3 w-3 fill-current" />
              Default
            </Badge>
          )}
        </Link>
      </TableCell>
      {isColumnVisible("type") && (
        <TableCell className={cn("hidden md:table-cell", cellClass)}>
          <Badge variant={scheduleTypeVariant[schedule.scheduleType] ?? "outline"} className="gap-1">
            {(() => {
              const TypeIcon = scheduleTypeIcons[schedule.scheduleType] ?? Clock
              return <TypeIcon className="h-3 w-3" />
            })()}
            {scheduleTypeLabels[schedule.scheduleType] ?? schedule.scheduleType}
          </Badge>
        </TableCell>
      )}
      {isColumnVisible("timezone") && (
        <TableCell className={cn("hidden md:table-cell", cellClass)}>
          <Badge variant="outline" className="gap-1 font-normal text-muted-foreground">
            <Globe className="h-3 w-3" />
            {schedule.timezone.replace(/_/g, " ")}
          </Badge>
        </TableCell>
      )}
      {isColumnVisible("entries") && (
        <TableCell className={cn("hidden lg:table-cell", cellClass)}>
          {schedule.entries && schedule.entries.length > 0 ? (
            <span className="text-sm text-muted-foreground">
              {schedule.entries.length} {schedule.entries.length === 1 ? "entry" : "entries"}
            </span>
          ) : (
            <span className="text-sm text-muted-foreground">--</span>
          )}
        </TableCell>
      )}
      {isColumnVisible("status") && (
        <TableCell className={cellClass}>
          <ScheduleStatusBadge scheduleId={schedule.id} />
        </TableCell>
      )}
      <TableCell className={cn("text-right", cellClass)}>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              data-slot="dropdown"
              onClick={(e) => e.stopPropagation()}
            >
              <MoreVertical className="h-4 w-4" />
              <span className="sr-only">Actions</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link to="/schedules/$scheduleId" params={{ scheduleId: schedule.id }}>
                <Eye className="mr-2 h-4 w-4" />
                View details
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link to="/schedules/$scheduleId" params={{ scheduleId: schedule.id }} search={{ edit: true }}>
                <Pencil className="mr-2 h-4 w-4" />
                Edit
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => {
                navigator.clipboard.writeText(schedule.id)
                toast.success("Schedule ID copied to clipboard")
              }}
            >
              <Copy className="mr-2 h-4 w-4" />
              Copy Schedule ID
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="text-destructive focus:text-destructive"
              onClick={() => setItemToDelete({ id: schedule.id, name: schedule.name })}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>

      <AlertDialog open={!!itemToDelete} onOpenChange={(open) => !open && setItemToDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete schedule?</AlertDialogTitle>
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
    </TableRow>
  )
}
