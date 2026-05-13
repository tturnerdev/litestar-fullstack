import { createFileRoute, Link } from "@tanstack/react-router"
import { Download, Home, Plus, Search, SlidersHorizontal, X } from "lucide-react"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { type LocationFreshnessState, LocationList } from "@/components/locations/location-list"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { DataFreshness } from "@/components/ui/data-freshness"
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import type { Location } from "@/lib/api/hooks/locations"
import { type CsvHeader, exportToCsv } from "@/lib/csv-export"
import { useSettingsStore } from "@/lib/settings-store"

export const Route = createFileRoute("/_app/locations/")({
  validateSearch: (
    search: Record<string, unknown>,
  ): {
    q?: string
    page?: number
    type?: string
    sort?: string
    order?: string
  } => ({
    q: typeof search.q === "string" && search.q ? search.q : undefined,
    page: Number(search.page) > 1 ? Number(search.page) : undefined,
    type: typeof search.type === "string" && search.type ? search.type : undefined,
    sort: typeof search.sort === "string" && search.sort ? search.sort : undefined,
    order: typeof search.order === "string" && (search.order === "asc" || search.order === "desc") ? search.order : undefined,
  }),
  component: LocationsPage,
})

// -- Column visibility ---------------------------------------------------------

const COLUMN_VISIBILITY_KEY = "locations-columns"

const TOGGLEABLE_COLUMNS = [
  { key: "type", label: "Type" },
  { key: "address", label: "Address" },
  { key: "subLocations", label: "Sub-locations" },
  { key: "description", label: "Description" },
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

function LocationsPage() {
  useDocumentTitle("Locations")
  const compactMode = useSettingsStore((s) => s.compactMode)
  const cellClass = compactMode ? "py-1 px-2 text-xs" : ""

  const { q: searchParam, page: pageParam, type: typeParam, sort: sortParam, order: orderParam } = Route.useSearch()
  const navigate = Route.useNavigate()
  const searchInputRef = useRef<HTMLInputElement>(null)

  // Data freshness state lifted from LocationList
  const [freshness, setFreshness] = useState<LocationFreshnessState | null>(null)

  // Locations data lifted from LocationList for page-level export
  const [locations, setLocations] = useState<Location[]>([])

  // Export all visible locations
  const handleExportAll = useCallback(() => {
    if (!locations.length) return
    exportToCsv("locations", csvHeaders, locations)
  }, [locations])

  // Derive filter state from URL search params
  const search = searchParam ?? ""
  const typeFilter = typeParam ?? "all"

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

  // Keyboard shortcuts: "/" to focus search, "n" opens the create page
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
        navigate({ to: "/locations/new" })
      }
    }
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [navigate])

  // Resolved search params for the child component
  const resolvedSearchParams = useMemo(
    () => ({
      q: debouncedSearch || undefined,
      page: pageParam,
      type: typeParam,
      sort: sortParam,
      order: orderParam,
    }),
    [debouncedSearch, pageParam, typeParam, sortParam, orderParam],
  )

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

  const hasActiveFilters = search !== "" || typeFilter !== "all"

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
          <BreadcrumbPage>Locations</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Workspace"
        title="Locations"
        description="Manage office locations and addresses."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-2">
            {freshness && <DataFreshness dataUpdatedAt={freshness.dataUpdatedAt} onRefresh={freshness.refetch} isRefreshing={freshness.isRefetching} />}
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
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!locations.length}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
            <Button size="sm" asChild>
              <Link to="/locations/new">
                <Plus className="mr-2 h-4 w-4" /> Add location
                <kbd className="ml-1.5 hidden rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground sm:inline">N</kbd>
              </Link>
            </Button>
          </div>
        }
      />

      {/* Search & filter bar */}
      <PageSection>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative max-w-md flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              ref={searchInputRef}
              placeholder="Search locations..."
              value={searchInput}
              onKeyDown={(e) => {
                if (e.key === "Escape") {
                  setSearchInput("")
                  e.currentTarget.blur()
                }
              }}
              onChange={(e) => setSearchInput(e.target.value)}
              className="pl-10 pr-8"
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
              <kbd className="pointer-events-none absolute right-8 top-1/2 -translate-y-1/2 hidden rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground sm:inline">
                /
              </kbd>
            )}
          </div>
          <Select
            value={typeFilter}
            onValueChange={(v) => {
              navigate({
                search: (prev) => ({
                  ...prev,
                  type: v !== "all" ? v : undefined,
                  page: undefined,
                }),
              })
            }}
          >
            <SelectTrigger className="w-full sm:w-[180px]">
              <SelectValue placeholder="All types" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All types</SelectItem>
              <SelectItem value="ADDRESSED">Addressed</SelectItem>
              <SelectItem value="PHYSICAL">Physical</SelectItem>
            </SelectContent>
          </Select>
          {hasActiveFilters && (
            <Button
              variant="ghost"
              size="sm"
              className="text-xs text-muted-foreground"
              onClick={() => {
                setSearchInput("")
                navigate({
                  search: (prev) => ({
                    ...prev,
                    q: undefined,
                    type: undefined,
                    page: undefined,
                  }),
                })
              }}
            >
              Clear filters
            </Button>
          )}
        </div>
      </PageSection>

      <PageSection delay={0.1}>
        <SectionErrorBoundary name="Location List">
          <LocationList
            searchParams={resolvedSearchParams}
            navigate={navigate}
            cellClass={cellClass}
            isColumnVisible={isColumnVisible}
            onSearchInputChange={setSearchInput}
            onFreshnessChange={setFreshness}
            onLocationsChange={setLocations}
          />
        </SectionErrorBoundary>
      </PageSection>
    </PageContainer>
  )
}
