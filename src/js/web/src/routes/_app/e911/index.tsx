import { createFileRoute, Link } from "@tanstack/react-router"
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Download,
  Eye,
  Home,
  Loader2,
  MoreVertical,
  Pencil,
  Plus,
  Search,
  ShieldAlert,
  SlidersHorizontal,
  Trash2,
  X,
  XCircle,
} from "lucide-react"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
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
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton, SkeletonCard } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import {
  type E911Registration,
  type UnregisteredPhoneNumber,
  useDeleteE911Registration,
  useE911Registrations,
  useUnregisteredPhoneNumbers,
  useValidateE911Registration,
} from "@/lib/api/hooks/e911"
import { useAuthStore } from "@/lib/auth"
import { type CsvHeader, exportToCsv } from "@/lib/csv-export"
import { useSettingsStore } from "@/lib/settings-store"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/e911/")({
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
    order: typeof search.order === "string" && (search.order === "asc" || search.order === "desc") ? search.order : undefined,
  }),
  component: E911Page,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_STORAGE_KEY = "e911-page-size"

function getStoredPageSize(): number {
  try {
    const stored = localStorage.getItem(PAGE_SIZE_STORAGE_KEY)
    if (stored) {
      const parsed = Number(stored)
      if ((PAGE_SIZES as readonly number[]).includes(parsed)) return parsed
    }
  } catch {
    /* localStorage unavailable */
  }
  return DEFAULT_PAGE_SIZE
}

const csvHeaders: CsvHeader<E911Registration>[] = [
  { label: "Phone Number", accessor: (r) => r.phoneNumberDisplay ?? "" },
  { label: "Phone Number Label", accessor: (r) => r.phoneNumberLabel ?? "" },
  { label: "Address Line 1", accessor: (r) => r.addressLine1 },
  { label: "Address Line 2", accessor: (r) => r.addressLine2 ?? "" },
  { label: "City", accessor: (r) => r.city },
  { label: "State", accessor: (r) => r.state },
  { label: "Postal Code", accessor: (r) => r.postalCode },
  { label: "Country", accessor: (r) => r.country },
  { label: "Validated", accessor: (r) => (r.validated ? "Yes" : "No") },
  { label: "Validated At", accessor: (r) => r.validatedAt ?? "" },
  { label: "Carrier Reg ID", accessor: (r) => r.carrierRegistrationId ?? "" },
  { label: "Location", accessor: (r) => r.locationName ?? "" },
]

// -- Column visibility ---------------------------------------------------------

const COLUMN_VISIBILITY_KEY = "e911-columns"

const TOGGLEABLE_COLUMNS = [
  { key: "address", label: "Address" },
  { key: "cityState", label: "City / State" },
  { key: "validated", label: "Validated" },
  { key: "carrierRegId", label: "Carrier Reg ID" },
] as const

type ColumnVisibility = Record<string, boolean>

function loadColumnVisibility(): ColumnVisibility {
  try {
    return JSON.parse(localStorage.getItem(COLUMN_VISIBILITY_KEY) ?? "{}")
  } catch {
    return {}
  }
}

// -- Filter options -----------------------------------------------------------

const validationStatusOptions: FilterOption[] = [
  { value: "validated", label: "Validated" },
  { value: "pending", label: "Pending" },
]

// -- E911 Row -----------------------------------------------------------------

function E911Row({
  reg,
  index,
  selected,
  onToggle,
  onRowClick,
  cellClass,
  isColumnVisible,
}: {
  reg: E911Registration
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
  cellClass: string
  isColumnVisible: (col: string) => boolean
}) {
  const validateMutation = useValidateE911Registration(reg.id)
  const deleteMutation = useDeleteE911Registration()

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
          aria-label={`Select ${reg.phoneNumberDisplay ?? reg.id}`}
        />
      </TableCell>
      <TableCell className={cellClass}>
        <Link to="/e911/$registrationId" params={{ registrationId: reg.id }} className="group flex flex-col gap-0.5" onClick={(e) => e.stopPropagation()}>
          <span className="font-medium group-hover:underline font-mono text-sm">{reg.phoneNumberDisplay ?? "No number"}</span>
          {reg.phoneNumberLabel && <span className="text-xs text-muted-foreground">{reg.phoneNumberLabel}</span>}
        </Link>
      </TableCell>
      {isColumnVisible("address") && (
        <TableCell className={cellClass}>
          <Link to="/e911/$registrationId" params={{ registrationId: reg.id }} className="group-hover:underline text-sm" onClick={(e) => e.stopPropagation()}>
            {reg.addressLine1}
            {reg.addressLine2 ? `, ${reg.addressLine2}` : ""}
          </Link>
        </TableCell>
      )}
      {isColumnVisible("cityState") && (
        <TableCell className={cn("hidden md:table-cell", cellClass)}>
          <span className="text-sm">
            {reg.city}, {reg.state} {reg.postalCode}
          </span>
        </TableCell>
      )}
      {isColumnVisible("validated") && (
        <TableCell className={cellClass}>
          {reg.validated ? (
            <Badge className="bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/30">
              <CheckCircle2 className="mr-1 h-3 w-3" />
              Validated
            </Badge>
          ) : (
            <Badge variant="outline" className="border-red-500/30 text-red-600 dark:text-red-400">
              <XCircle className="mr-1 h-3 w-3" />
              Pending
            </Badge>
          )}
        </TableCell>
      )}
      {isColumnVisible("carrierRegId") && (
        <TableCell className={cn("hidden md:table-cell", cellClass)}>
          {reg.carrierRegistrationId ? (
            <span className="font-mono text-xs text-muted-foreground">{reg.carrierRegistrationId}</span>
          ) : (
            <span className="text-xs text-muted-foreground">--</span>
          )}
        </TableCell>
      )}
      <TableCell className={cn("text-right", cellClass)}>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" className="h-8 w-8 p-0" data-slot="dropdown" onClick={(e) => e.stopPropagation()}>
              <MoreVertical className="h-4 w-4" />
              <span className="sr-only">Actions for {reg.phoneNumberDisplay ?? reg.id}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link to="/e911/$registrationId" params={{ registrationId: reg.id }}>
                <Eye className="mr-2 h-4 w-4" />
                View details
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link to="/e911/$registrationId" params={{ registrationId: reg.id }} search={{ edit: true }}>
                <Pencil className="mr-2 h-4 w-4" />
                Edit
              </Link>
            </DropdownMenuItem>
            {!reg.validated && (
              <DropdownMenuItem
                disabled={validateMutation.isPending}
                onClick={() =>
                  validateMutation.mutate(undefined, {
                    onSuccess: () => toast.success("E911 registration validated"),
                    onError: (err) =>
                      toast.error("Failed to validate E911 registration", {
                        description: err instanceof Error ? err.message : undefined,
                      }),
                  })
                }
              >
                {validateMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <CheckCircle2 className="mr-2 h-4 w-4" />}
                Validate
              </DropdownMenuItem>
            )}
            <DropdownMenuSeparator />
            <DropdownMenuItem
              variant="destructive"
              disabled={deleteMutation.isPending}
              onClick={() =>
                deleteMutation.mutate(reg.id, {
                  onSuccess: () => toast.success("E911 registration deleted"),
                  onError: (err) =>
                    toast.error("Failed to delete E911 registration", {
                      description: err instanceof Error ? err.message : undefined,
                    }),
                })
              }
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

// -- Register dialog ----------------------------------------------------------

// -- Main page ----------------------------------------------------------------

function E911Page() {
  useDocumentTitle("E911 Addresses")
  const compactMode = useSettingsStore((s) => s.compactMode)
  const cellClass = compactMode ? "py-1 px-2 text-xs" : ""

  const { currentTeam } = useAuthStore()
  const { q: searchParam, page: pageParam, status: statusParam, sort: sortParam, order: orderParam } = Route.useSearch()
  const navigate = Route.useNavigate()
  const teamId = currentTeam?.id ?? ""

  // Column visibility
  const [columnVisibility, setColumnVisibility] = useState<ColumnVisibility>(loadColumnVisibility)
  const isColumnVisible = useCallback((col: string) => columnVisibility[col] !== false, [columnVisibility])
  const toggleColumn = useCallback((col: string) => {
    setColumnVisibility((prev) => {
      const updated = { ...prev, [col]: prev[col] === false }
      localStorage.setItem(COLUMN_VISIBILITY_KEY, JSON.stringify(updated))
      return updated
    })
  }, [])

  // Derive filter state from URL search params
  const search = searchParam ?? ""
  const page = pageParam ?? 1
  const sortKey = sortParam ?? null
  const sortDir: SortDirection = (orderParam as SortDirection) ?? null
  const statusFilter = useMemo(() => (statusParam ? statusParam.split(",").filter(Boolean) : []), [statusParam])

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

  const handlePageSizeChange = useCallback(
    (value: string) => {
      const size = Number(value)
      setPageSize(size)
      navigate({ search: (prev) => ({ ...prev, page: undefined }), replace: true })
      try {
        localStorage.setItem(PAGE_SIZE_STORAGE_KEY, String(size))
      } catch {
        /* localStorage unavailable */
      }
    },
    [navigate],
  )

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

  const searchInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey) {
        const target = e.target as HTMLElement
        if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return
        e.preventDefault()
        searchInputRef.current?.focus()
      }
    }
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [])

  const { data, isLoading, isRefetching, isError, refetch } = useE911Registrations({
    page,
    pageSize,
    search: debouncedSearch || undefined,
    teamId: teamId || undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
  })

  const deleteMutation = useDeleteE911Registration()
  const { data: unregistered } = useUnregisteredPhoneNumbers(teamId)

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  const items = data?.items ?? []

  // Apply client-side status filter
  const filteredItems = useMemo(() => {
    if (statusFilter.length === 0) return items
    return items.filter((reg) => {
      if (statusFilter.includes("validated") && reg.validated) return true
      if (statusFilter.includes("pending") && !reg.validated) return true
      return false
    })
  }, [items, statusFilter])

  // Registration summary stats (computed from ALL items on the current page)
  const registrationStats = useMemo(() => {
    const all = data?.items ?? []
    let validated = 0
    let pending = 0
    for (const reg of all) {
      if (reg.validated) validated++
      else pending++
    }
    return { validated, pending, total: data?.total ?? 0 }
  }, [data?.items, data?.total])

  // Selection helpers
  const allVisibleIds = useMemo(() => filteredItems.map((r) => r.id), [filteredItems])
  const allSelected = filteredItems.length > 0 && filteredItems.every((r) => selectedIds.has(r.id))
  const someSelected = filteredItems.some((r) => selectedIds.has(r.id))

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

  // Bulk actions
  const bulkActions = useMemo(
    () => [
      createBulkDeleteAction(
        async (id) => {
          await deleteMutation.mutateAsync(id)
        },
        () => {
          setSelectedIds(new Set())
          deleteMutation.reset()
        },
      ),
      createExportAction<E911Registration>("e911-registrations-selected", csvHeaders, (ids) => filteredItems.filter((r) => ids.includes(r.id))),
    ],
    [filteredItems, deleteMutation],
  )

  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / pageSize))
  const hasData = filteredItems.length > 0
  const hasAnyItems = items.length > 0
  const unregisteredCount = unregistered?.length ?? 0
  const activeFilterCount = statusFilter.length

  const handleRowClick = useCallback(
    (registrationId: string) => {
      navigate({ to: "/e911/$registrationId", params: { registrationId } })
    },
    [navigate],
  )

  const handleExportAll = useCallback(() => {
    if (!filteredItems.length) return
    exportToCsv("e911-registrations", csvHeaders, filteredItems)
  }, [filteredItems])

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
          <BreadcrumbPage>E911 Addresses</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Compliance"
        title={
          <span className="flex items-center gap-3">
            E911 Addresses
            {unregisteredCount > 0 && (
              <Badge variant="outline" className="border-amber-500/40 text-amber-600 dark:text-amber-400 text-xs font-normal">
                <AlertTriangle className="mr-1 h-3 w-3" />
                {unregisteredCount} unregistered
              </Badge>
            )}
          </span>
        }
        description="Manage E911 emergency address registrations for your phone numbers."
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
            {teamId && (
              <Button size="sm" asChild>
                <Link to="/e911/new">
                  <Plus className="mr-2 h-4 w-4" /> Register Address
                </Link>
              </Button>
            )}
          </div>
        }
      />

      {/* Summary stats */}
      <SectionErrorBoundary name="E911 Registration Summary">
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
                <span className="ml-0.5 font-semibold text-foreground">{registrationStats.total}</span>
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-400">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                Validated
                <span className="ml-0.5 font-semibold">{registrationStats.validated}</span>
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1 text-xs font-medium text-amber-700 dark:text-amber-400">
                <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
                Pending
                <span className="ml-0.5 font-semibold">{registrationStats.pending}</span>
              </span>
            </>
          )}
        </div>
      </SectionErrorBoundary>

      {/* Search */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input ref={searchInputRef} placeholder="Search by address..." value={searchInput} onChange={(e) => setSearchInput(e.target.value)} className="pl-9 pr-8" />
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
          <FilterDropdown
            label="Status"
            options={validationStatusOptions}
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

      {/* Unregistered numbers warning */}
      {unregisteredCount > 0 && (
        <PageSection delay={0.05}>
          <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-500" />
              <div className="flex-1">
                <p className="font-medium text-sm">
                  {unregisteredCount} phone number{unregisteredCount === 1 ? "" : "s"} without E911 registration
                </p>
                <p className="mt-1 text-sm text-muted-foreground">
                  The following numbers do not have E911 addresses registered. Emergency services may not be able to locate callers using these numbers.
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {(unregistered ?? []).map((pn: UnregisteredPhoneNumber) => (
                    <Badge key={pn.id} variant="outline" className="border-amber-500/40 text-amber-600 dark:text-amber-400">
                      <AlertTriangle className="mr-1 h-3 w-3" />
                      {pn.number}
                      {pn.label ? ` (${pn.label})` : ""}
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </PageSection>
      )}

      {/* Registrations table */}
      <PageSection delay={0.1}>
        <SectionErrorBoundary name="E911 Registrations Table">
          {isLoading ? (
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
              {["sk-card-0", "sk-card-1", "sk-card-2"].map((key) => (
                <SkeletonCard key={key} />
              ))}
            </div>
          ) : isError ? (
            <EmptyState
              icon={AlertCircle}
              title="Unable to load E911 registrations"
              description="Something went wrong while fetching your E911 registrations. Please try again."
              action={
                <Button variant="outline" size="sm" onClick={() => refetch()}>
                  Try again
                </Button>
              }
            />
          ) : !hasAnyItems && !search && activeFilterCount === 0 ? (
            <EmptyState
              icon={ShieldAlert}
              title="No E911 registrations"
              description="Register E911 addresses for your phone numbers to ensure emergency services can locate callers."
              action={
                teamId ? (
                  <Button size="sm" asChild>
                    <Link to="/e911/new">
                      <Plus className="mr-2 h-4 w-4" /> Register Address
                    </Link>
                  </Button>
                ) : undefined
              }
            />
          ) : !hasData ? (
            <EmptyState
              icon={ShieldAlert}
              variant="no-results"
              title="No results found"
              description="No E911 registrations match your current filters. Try adjusting your search or filters."
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
          ) : (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-xs text-muted-foreground">
                  {data?.total ?? filteredItems.length} registration{(data?.total ?? filteredItems.length) === 1 ? "" : "s"}
                  {activeFilterCount > 0 && " (filtered)"}
                </p>
                {totalPages > 1 && (
                  <p className="text-xs text-muted-foreground">
                    Page {page} of {totalPages}
                  </p>
                )}
              </div>

              <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
                <Table aria-label="E911 Registrations" aria-busy={isLoading || isRefetching}>
                  <TableHeader className="sticky top-0 z-10 bg-background">
                    <TableRow>
                      <TableHead className="w-10">
                        <Checkbox checked={allSelected} indeterminate={someSelected && !allSelected} onChange={toggleAll} aria-label="Select all registrations" />
                      </TableHead>
                      <SortableHeader label="Phone Number" sortKey="phone_number_display" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />
                      {isColumnVisible("address") && (
                        <SortableHeader label="Address" sortKey="address_line1" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />
                      )}
                      {isColumnVisible("cityState") && (
                        <SortableHeader label="City / State" sortKey="city" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} className="hidden md:table-cell" />
                      )}
                      {isColumnVisible("validated") && (
                        <SortableHeader label="Validated" sortKey="validated" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />
                      )}
                      {isColumnVisible("carrierRegId") && <TableHead className="hidden md:table-cell">Carrier Reg ID</TableHead>}
                      <TableHead className="w-16 text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredItems.map((reg: E911Registration, index: number) => (
                      <E911Row
                        key={reg.id}
                        reg={reg}
                        index={index}
                        selected={selectedIds.has(reg.id)}
                        onToggle={() => toggleOne(reg.id)}
                        onRowClick={() => handleRowClick(reg.id)}
                        cellClass={cellClass}
                        isColumnVisible={isColumnVisible}
                      />
                    ))}
                  </TableBody>
                </Table>
              </div>
              <div className="sr-only" aria-live="polite" aria-atomic="true">
                {!isLoading && `Showing ${filteredItems.length} of ${data?.total ?? filteredItems.length} results, page ${page}`}
              </div>

              {/* Pagination */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">Rows per page</span>
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
      <BulkActionBar selectedCount={selectedIds.size} selectedIds={Array.from(selectedIds)} onClearSelection={() => setSelectedIds(new Set())} actions={bulkActions} />
    </PageContainer>
  )
}
