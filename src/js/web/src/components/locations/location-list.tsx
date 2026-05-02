import { Link } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useState } from "react"
import { AlertCircle, Building2, Download, Eye, MapPin, MoreVertical, Pencil, Search, Trash2, X } from "lucide-react"
import { cn } from "@/lib/utils"
import { Badge } from "@/components/ui/badge"
import { BulkActionBar, createBulkDeleteAction, createExportAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton, SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
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
import { buttonVariants } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useAuthStore } from "@/lib/auth"
import { type Location, useBulkDeleteLocations, useDeleteLocation, useLocations } from "@/lib/api/hooks/locations"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { useDebouncedValue } from "@/hooks/use-debounced-value"

const getId = (loc: Location) => loc.id

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_STORAGE_KEY = "locations-page-size"

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

const csvHeaders: CsvHeader<Location>[] = [
  { label: "Name", accessor: (l) => l.name },
  { label: "Type", accessor: (l) => l.locationType },
  { label: "Address", accessor: (l) => l.addressLine1 ?? "" },
  { label: "City", accessor: (l) => l.city ?? "" },
  { label: "State", accessor: (l) => l.state ?? "" },
  { label: "Postal Code", accessor: (l) => l.postalCode ?? "" },
  { label: "Country", accessor: (l) => l.country ?? "" },
  { label: "Description", accessor: (l) => l.description ?? "" },
]

interface LocationSearchParams {
  q?: string
  page?: number
  type?: string
  sort?: string
  order?: string
}

type NavigateFn = (opts: {
  to?: string
  params?: Record<string, string>
  search?: LocationSearchParams | ((prev: LocationSearchParams) => LocationSearchParams)
  replace?: boolean
}) => void

export function LocationList({
  searchParams,
  navigate,
  cellClass = "",
  isColumnVisible = () => true,
}: {
  searchParams: LocationSearchParams
  navigate: NavigateFn
  cellClass?: string
  isColumnVisible?: (col: string) => boolean
}) {
  const { currentTeam } = useAuthStore()

  // Derive filter state from URL search params
  const search = searchParams.q ?? ""
  const page = searchParams.page ?? 1
  const typeFilter = searchParams.type ?? "all"
  const sortKey = searchParams.sort ?? null
  const sortDir: SortDirection = (searchParams.order as SortDirection) ?? null

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

  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [pageSize, setPageSize] = useState(getStoredPageSize)

  // Persist page size preference
  const handlePageSizeChange = useCallback((value: string) => {
    const size = Number(value)
    setPageSize(size)
    navigate({ search: (prev) => ({ ...prev, page: undefined }), replace: true })
    try {
      localStorage.setItem(PAGE_SIZE_STORAGE_KEY, value)
    } catch {
      // localStorage unavailable
    }
  }, [navigate])

  const teamId = currentTeam?.id ?? ""

  const { data, isLoading, isError, refetch } = useLocations({
    teamId,
    page,
    pageSize,
    search: debouncedSearch || undefined,
    locationType: typeFilter !== "all" ? typeFilter : undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
  })

  const locations = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / pageSize))

  const bulk = useBulkDeleteLocations(teamId)

  // Selection helpers
  const allSelected = locations.length > 0 && locations.every((loc) => selectedIds.has(loc.id))
  const someSelected = locations.some((loc) => selectedIds.has(loc.id))

  const toggleAll = useCallback(() => {
    if (allSelected) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(locations.map(getId)))
    }
  }, [allSelected, locations])

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
        (id) => bulk.deleteOne(id),
        () => {
          bulk.invalidate()
          setSelectedIds(new Set())
        },
        { label: "Delete Selected" },
      ),
      createExportAction<Location>(
        "locations-selected",
        csvHeaders,
        (ids) => locations.filter((loc) => ids.includes(loc.id)),
      ),
    ],
    [bulk, locations],
  )

  // Export all visible
  const handleExportAll = useCallback(() => {
    if (!locations.length) return
    exportToCsv("locations", csvHeaders, locations)
  }, [locations])

  // Row click handler
  const handleRowClick = useCallback(
    (locationId: string) => {
      navigate({ to: "/locations/$locationId", params: { locationId } })
    },
    [navigate],
  )

  const hasActiveFilters = search !== "" || typeFilter !== "all"

  // Keyboard shortcuts: ArrowLeft/ArrowRight for pagination
  // NOTE: This useEffect must be above all conditional returns to satisfy
  // the rules of hooks (consistent hook call order on every render).
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return
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

  if (!currentTeam) {
    return (
      <EmptyState
        icon={Building2}
        title="Select a team first"
        description="Locations belong to teams. Please select a team from the sidebar to view and manage locations."
      />
    )
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <Skeleton className="h-7 w-28 rounded-full" />
        </div>
        <SkeletonTable rows={6} />
      </div>
    )
  }

  if (isError) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load locations"
        description="Something went wrong while fetching your locations. Please try again."
        action={
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            Try again
          </Button>
        }
      />
    )
  }

  if (locations.length === 0 && !search && typeFilter === "all") {
    return (
      <EmptyState
        icon={MapPin}
        title="No locations yet"
        description="Locations help you track where devices and extensions are physically placed. Start by creating an addressed location like an office or branch."
        action={
          <Button size="sm" asChild>
            <Link to="/locations/new">Create location</Link>
          </Button>
        }
      />
    )
  }

  return (
    <>
      <div className="space-y-4">
        {/* Summary stats */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-muted/50 px-3 py-1 text-xs font-medium text-muted-foreground">
            Total
            <span className="ml-0.5 font-semibold text-foreground">{total}</span>
          </span>
        </div>

        {/* Search & filter bar */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative max-w-md flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search locations..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              className="pl-10 pr-8"
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
          <Select value={typeFilter} onValueChange={(v) => {
            navigate({
              search: (prev) => ({
                ...prev,
                type: v !== "all" ? v : undefined,
                page: undefined,
              }),
            })
          }}>
            <SelectTrigger className="w-full sm:w-[180px]">
              <SelectValue placeholder="All types" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All types</SelectItem>
              <SelectItem value="ADDRESSED">Addressed</SelectItem>
              <SelectItem value="PHYSICAL">Physical</SelectItem>
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" onClick={handleExportAll} disabled={locations.length === 0}>
            <Download className="mr-2 h-4 w-4" />
            Export
          </Button>
        </div>

        {/* Result count & pagination info */}
        {locations.length > 0 && (
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              {total} location{total === 1 ? "" : "s"}
              {hasActiveFilters && " (filtered)"}
            </p>
            <div className="flex items-center gap-3">
              {hasActiveFilters && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-xs text-muted-foreground"
                  onClick={() => {
                    setSearchInput("")
                    navigate({
                      search: {
                        q: undefined,
                        type: undefined,
                        sort: searchParams.sort,
                        order: searchParams.order,
                        page: undefined,
                      },
                    })
                  }}
                >
                  Clear filters
                </Button>
              )}
              {totalPages > 1 && (
                <p className="text-xs text-muted-foreground">
                  Page {page} of {totalPages}
                </p>
              )}
            </div>
          </div>
        )}

        {/* Table */}
        {locations.length > 0 ? (
          <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
            <Table aria-label="Locations">
              <TableHeader className="sticky top-0 z-10 bg-background">
                <TableRow>
                  <TableHead className="w-10">
                    <Checkbox
                      checked={allSelected}
                      indeterminate={someSelected && !allSelected}
                      onChange={toggleAll}
                      aria-label="Select all locations"
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
                      sortKey="location_type"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                  )}
                  {isColumnVisible("address") && (
                    <TableHead>Address</TableHead>
                  )}
                  {isColumnVisible("subLocations") && (
                    <TableHead>Sub-locations</TableHead>
                  )}
                  {isColumnVisible("description") && (
                    <TableHead>Description</TableHead>
                  )}
                  <TableHead className="w-16 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {locations.map((location, index) => (
                  <LocationRow
                    key={location.id}
                    location={location}
                    index={index}
                    selected={selectedIds.has(location.id)}
                    onToggle={() => toggleOne(location.id)}
                    onRowClick={() => handleRowClick(location.id)}
                    teamId={teamId}
                    cellClass={cellClass}
                    isColumnVisible={isColumnVisible}
                  />
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <EmptyState
            icon={MapPin}
            variant="no-results"
            title="No results found"
            description={`No locations match ${search ? `"${search}"` : "the selected filter"}. Try adjusting your search or filter criteria.`}
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
                      sort: undefined,
                      order: undefined,
                      page: undefined,
                    },
                  })
                }}
              >
                Clear filters
              </Button>
            }
          />
        )}

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

      {/* Bulk action bar */}
      <BulkActionBar
        selectedCount={selectedIds.size}
        selectedIds={Array.from(selectedIds)}
        onClearSelection={() => setSelectedIds(new Set())}
        actions={bulkActions}
      />
    </>
  )
}

// ---------------------------------------------------------------------------
// Location Row
// ---------------------------------------------------------------------------

function LocationRow({
  location,
  index,
  selected,
  onToggle,
  onRowClick,
  teamId,
  cellClass = "",
  isColumnVisible = () => true,
}: {
  location: Location
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
  teamId: string
  cellClass?: string
  isColumnVisible?: (col: string) => boolean
}) {
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const deleteMutation = useDeleteLocation(teamId)

  const handleDelete = useCallback(() => {
    deleteMutation.mutate(location.id, {
      onSettled: () => setShowDeleteConfirm(false),
    })
  }, [deleteMutation, location.id])

  const isAddressed = location.locationType === "ADDRESSED"
  const childCount = location.children?.length ?? 0

  const addressParts = [location.addressLine1, location.city, location.state, location.postalCode].filter(Boolean)
  const addressSummary = addressParts.join(", ")

  const description = location.description ?? ""
  const isDescriptionTruncated = description.length > 80
  const truncatedDescription = isDescriptionTruncated ? `${description.slice(0, 80)}...` : description

  const isAddressLong = addressSummary.length > 50

  return (
    <>
    <TableRow
      data-state={selected ? "selected" : undefined}
      className={`cursor-pointer hover:bg-muted/50 transition-colors ${index % 2 === 1 ? "bg-muted/20" : ""}`}
      onClick={(e) => {
        // Don't navigate when clicking on checkbox or dropdown
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
          aria-label={`Select ${location.name}`}
        />
      </TableCell>
      <TableCell className={cellClass}>
        <Link
          to="/locations/$locationId"
          params={{ locationId: location.id }}
          className="font-medium hover:underline"
          onClick={(e) => e.stopPropagation()}
        >
          {location.name}
        </Link>
      </TableCell>
      {isColumnVisible("type") && (
        <TableCell className={cellClass}>
          <Badge variant={isAddressed ? "default" : "secondary"} className="inline-flex items-center gap-1 text-[10px]">
            {isAddressed ? (
              <>
                <Building2 className="h-3 w-3" />
                Addressed
              </>
            ) : (
              <>
                <MapPin className="h-3 w-3" />
                Physical
              </>
            )}
          </Badge>
        </TableCell>
      )}
      {isColumnVisible("address") && (
        <TableCell className={cellClass}>
          {addressSummary ? (
            <span className="inline-flex items-center gap-1.5 text-sm text-muted-foreground">
              <MapPin className="h-3.5 w-3.5 shrink-0 text-muted-foreground/70" />
              {isAddressLong ? (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span className="truncate max-w-[200px]">{addressSummary}</span>
                  </TooltipTrigger>
                  <TooltipContent>{addressSummary}</TooltipContent>
                </Tooltip>
              ) : (
                <span>{addressSummary}</span>
              )}
            </span>
          ) : (
            <span className="text-sm text-muted-foreground/50">--</span>
          )}
        </TableCell>
      )}
      {isColumnVisible("subLocations") && (
        <TableCell className={cellClass}>
          {isAddressed ? (
            <span className="text-sm text-muted-foreground">
              {childCount > 0 ? `${childCount} sub-location${childCount !== 1 ? "s" : ""}` : "--"}
            </span>
          ) : (
            <span className="text-sm text-muted-foreground/50">--</span>
          )}
        </TableCell>
      )}
      {isColumnVisible("description") && (
        <TableCell className={cellClass}>
          {truncatedDescription ? (
            isDescriptionTruncated ? (
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="text-sm text-muted-foreground cursor-default">{truncatedDescription}</span>
                </TooltipTrigger>
                <TooltipContent className="max-w-xs">{description}</TooltipContent>
              </Tooltip>
            ) : (
              <span className="text-sm text-muted-foreground">{truncatedDescription}</span>
            )
          ) : (
            <span className="text-sm text-muted-foreground/50">--</span>
          )}
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
              <span className="sr-only">Actions for {location.name}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link to="/locations/$locationId" params={{ locationId: location.id }}>
                <Eye className="mr-2 h-4 w-4" />
                View details
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link to="/locations/$locationId" params={{ locationId: location.id }} search={{ edit: true }}>
                <Pencil className="mr-2 h-4 w-4" />
                Edit
              </Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              variant="destructive"
              onClick={() => setShowDeleteConfirm(true)}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
    <AlertDialog open={showDeleteConfirm} onOpenChange={setShowDeleteConfirm}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete location</AlertDialogTitle>
          <AlertDialogDescription>
            Are you sure you want to delete &quot;{location.name}&quot;? This action cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction
            className={buttonVariants({ variant: "destructive" })}
            onClick={handleDelete}
          >
            Delete
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
    </>
  )
}
