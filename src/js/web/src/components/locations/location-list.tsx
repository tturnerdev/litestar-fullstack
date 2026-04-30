import { Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useMemo, useState } from "react"
import { AlertCircle, Building2, Eye, MapPin, MoreVertical, Pencil, Search } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { BulkActionBar, createBulkDeleteAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useAuthStore } from "@/lib/auth"
import { type Location, useBulkDeleteLocations, useLocations } from "@/lib/api/hooks/locations"

const getId = (loc: Location) => loc.id

export function LocationList() {
  const { currentTeam } = useAuthStore()
  const navigate = useNavigate()

  const [search, setSearch] = useState("")
  const [typeFilter, setTypeFilter] = useState<string>("all")
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  const teamId = currentTeam?.id ?? ""

  const { data, isLoading, isError } = useLocations({
    teamId,
    search: search || undefined,
    locationType: typeFilter !== "all" ? typeFilter : undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
    pageSize: 100,
  })

  const locations = data?.items ?? []
  const total = data?.total ?? 0

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
      setSortKey(next.sort)
      setSortDir(next.direction)
    },
    [sortKey, sortDir],
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
    ],
    [bulk],
  )

  // Row click handler
  const handleRowClick = useCallback(
    (locationId: string) => {
      navigate({ to: "/locations/$locationId", params: { locationId } })
    },
    [navigate],
  )

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
    return <SkeletonTable rows={6} />
  }

  if (isError) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load locations"
        description="Something went wrong while fetching your locations. Please try refreshing the page."
        action={
          <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
            Refresh page
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

  const hasActiveFilters = search !== "" || typeFilter !== "all"

  return (
    <>
      <div className="space-y-4">
        {/* Search & filter bar */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative max-w-md flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search locations..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-10"
            />
          </div>
          <Select value={typeFilter} onValueChange={setTypeFilter}>
            <SelectTrigger className="w-full sm:w-[180px]">
              <SelectValue placeholder="All types" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All types</SelectItem>
              <SelectItem value="ADDRESSED">Addressed</SelectItem>
              <SelectItem value="PHYSICAL">Physical</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Result count */}
        {locations.length > 0 && (
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              {hasActiveFilters
                ? `Showing ${locations.length} of ${total} location${total === 1 ? "" : "s"}`
                : `${total} location${total === 1 ? "" : "s"}`}
              {hasActiveFilters && " (filtered)"}
            </p>
            {hasActiveFilters && (
              <Button
                variant="ghost"
                size="sm"
                className="text-xs text-muted-foreground"
                onClick={() => {
                  setSearch("")
                  setTypeFilter("all")
                }}
              >
                Clear filters
              </Button>
            )}
          </div>
        )}

        {/* Table */}
        {locations.length > 0 ? (
          <div className="rounded-md border border-border/60 bg-card/80">
            <Table>
              <TableHeader>
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
                  <SortableHeader
                    label="Type"
                    sortKey="location_type"
                    currentSort={sortKey}
                    currentDirection={sortDir}
                    onSort={handleSort}
                  />
                  <TableHead>Address</TableHead>
                  <TableHead>Sub-locations</TableHead>
                  <TableHead>Description</TableHead>
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
                  setSearch("")
                  setTypeFilter("all")
                }}
              >
                Clear filters
              </Button>
            }
          />
        )}

        {/* Bottom count */}
        {locations.length > 0 && (
          <p className="text-xs text-muted-foreground text-center">
            Showing {locations.length} location{locations.length === 1 ? "" : "s"}
          </p>
        )}
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
}: {
  location: Location
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
}) {
  const isAddressed = location.locationType === "ADDRESSED"
  const childCount = location.children?.length ?? 0

  const addressParts = [location.addressLine1, location.city, location.state, location.postalCode].filter(Boolean)
  const addressSummary = addressParts.join(", ")

  const description = location.description ?? ""
  const isDescriptionTruncated = description.length > 80
  const truncatedDescription = isDescriptionTruncated ? `${description.slice(0, 80)}...` : description

  const isAddressLong = addressSummary.length > 50

  return (
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
      <TableCell>
        <Checkbox
          checked={selected}
          onChange={(e) => {
            e.stopPropagation()
            onToggle()
          }}
          aria-label={`Select ${location.name}`}
        />
      </TableCell>
      <TableCell>
        <Link
          to="/locations/$locationId"
          params={{ locationId: location.id }}
          className="font-medium hover:underline"
          onClick={(e) => e.stopPropagation()}
        >
          {location.name}
        </Link>
      </TableCell>
      <TableCell>
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
      <TableCell>
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
      <TableCell>
        {isAddressed ? (
          <span className="text-sm text-muted-foreground">
            {childCount > 0 ? `${childCount} sub-location${childCount !== 1 ? "s" : ""}` : "--"}
          </span>
        ) : (
          <span className="text-sm text-muted-foreground/50">--</span>
        )}
      </TableCell>
      <TableCell>
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
              <Link to="/locations/$locationId/edit" params={{ locationId: location.id }}>
                <Pencil className="mr-2 h-4 w-4" />
                Edit
              </Link>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  )
}
