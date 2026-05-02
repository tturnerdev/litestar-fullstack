import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useState } from "react"
import {
  AlertCircle,
  CheckCircle2,
  Download,
  Eye,
  MoreVertical,
  Pencil,
  Search,
  Trash2,
  Users,
  Users2,
  X,
  XCircle,
} from "lucide-react"
import { toast } from "sonner"
import { useQueryClient } from "@tanstack/react-query"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { DeleteTeamDialog } from "@/components/admin/delete-team-dialog"
import { EditTeamDialog } from "@/components/admin/edit-team-dialog"
import { Badge } from "@/components/ui/badge"
import { type BulkAction, BulkActionBar } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { DataFreshness } from "@/components/ui/data-freshness"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { useAdminTeams } from "@/lib/api/hooks/admin"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { adminDeleteTeam } from "@/lib/generated/api"
import type { AdminTeamSummary } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/admin/teams/")({
  component: AdminTeamsPage,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_STORAGE_KEY = "admin-teams-page-size"

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

const csvHeaders: CsvHeader<AdminTeamSummary>[] = [
  { label: "Name", accessor: (t) => t.name },
  { label: "Slug", accessor: (t) => t.slug },
  { label: "Members", accessor: (t) => t.memberCount ?? 0 },
  { label: "Active", accessor: (t) => (t.isActive ? "Yes" : "No") },
  { label: "Created At", accessor: (t) => formatDateTime(t.createdAt) },
]

const statusOptions: FilterOption[] = [
  { value: "active", label: "Active" },
  { value: "inactive", label: "Inactive" },
]

// -- Helpers ------------------------------------------------------------------


function ActiveStatusIndicator({ isActive }: { isActive: boolean | undefined }) {
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
      <XCircle className="h-3.5 w-3.5" />
      Inactive
    </span>
  )
}

function matchesStatusFilter(team: AdminTeamSummary, filters: string[]): boolean {
  if (filters.length === 0) return true
  for (const f of filters) {
    if (f === "active" && team.isActive === true) return true
    if (f === "inactive" && !team.isActive) return true
  }
  return false
}

function formatMemberCount(count: number | undefined): string {
  const n = count ?? 0
  return `${n} member${n === 1 ? "" : "s"}`
}

// -- Main page ----------------------------------------------------------------

function AdminTeamsPage() {
  useDocumentTitle("Admin — Teams")
  const navigate = useNavigate()

  // Filter & search state
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [statusFilter, setStatusFilter] = useState<string[]>([])
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(getStoredPageSize)

  // Reset page when debounced search changes
  useEffect(() => {
    setPage(1)
  }, [debouncedSearch])

  // Persist page size preference
  const handlePageSizeChange = useCallback((value: string) => {
    const size = Number(value)
    setPageSize(size)
    setPage(1)
    try {
      localStorage.setItem(PAGE_SIZE_STORAGE_KEY, value)
    } catch {
      // localStorage unavailable
    }
  }, [])

  // Sort state
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  // Queries & mutations
  const queryClient = useQueryClient()
  const { data, isLoading, isError, refetch, dataUpdatedAt, isRefetching } = useAdminTeams({
    page,
    pageSize,
    search: debouncedSearch || undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
  })

  // Export all visible
  const handleExportAll = useCallback(() => {
    if (!data?.items?.length) return
    exportToCsv("admin-teams", csvHeaders, data.items)
  }, [data?.items])

  // Apply client-side status filters
  const filteredItems = useMemo(() => {
    if (!data?.items) return []
    return data.items.filter((team) => matchesStatusFilter(team, statusFilter))
  }, [data?.items, statusFilter])

  // Selection helpers
  const allVisibleIds = useMemo(() => filteredItems.map((t) => t.id), [filteredItems])
  const allSelected = filteredItems.length > 0 && filteredItems.every((t) => selectedIds.has(t.id))
  const someSelected = filteredItems.some((t) => selectedIds.has(t.id))

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

  // Bulk actions
  const bulkActions = useMemo<BulkAction[]>(
    () => [
      {
        key: "delete",
        label: "Delete",
        icon: <Trash2 className="h-4 w-4" />,
        variant: "destructive",
        confirm: {
          title: "Delete selected teams?",
          description: "This action cannot be undone. All selected teams and their associations will be permanently deleted.",
        },
        onExecute: async (ids) => {
          let succeeded = 0
          let failed = 0
          for (const id of ids) {
            try {
              await adminDeleteTeam({ path: { team_id: id } })
              succeeded++
            } catch {
              failed++
            }
          }
          await queryClient.invalidateQueries({ queryKey: ["admin", "teams"] })
          setSelectedIds(new Set())
          if (failed === 0) {
            toast.success(`Deleted ${succeeded} team${succeeded !== 1 ? "s" : ""}`)
          } else {
            toast.warning(`${succeeded} deleted, ${failed} failed`)
          }
        },
      },
    ],
    [queryClient],
  )

  // Row click handler
  const handleRowClick = useCallback(
    (teamId: string) => {
      navigate({ to: "/admin/teams/$teamId", params: { teamId } })
    },
    [navigate],
  )

  // Computed
  const activeFilterCount = statusFilter.length
  const hasData = filteredItems.length > 0
  const hasAnyTeams = (data?.items.length ?? 0) > 0
  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / pageSize))

  // Keyboard shortcuts: ArrowLeft/ArrowRight for pagination
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return
      if (e.key === "ArrowLeft" && page > 1) {
        e.preventDefault()
        setPage((p) => Math.max(1, p - 1))
      }
      if (e.key === "ArrowRight" && page < totalPages) {
        e.preventDefault()
        setPage((p) => Math.min(totalPages, p + 1))
      }
    }
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [page, totalPages])

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Teams"
        description="View and manage all teams in the system."
        breadcrumbs={<AdminBreadcrumbs />}
        actions={
          <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!data?.items?.length}>
            <Download className="mr-2 h-4 w-4" />
            Export
          </Button>
        }
      />
      <AdminNav />

      {/* Search & filters */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search by team name or slug..."
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
            label="Status"
            options={statusOptions}
            selected={statusFilter}
            onChange={setStatusFilter}
          />
          {activeFilterCount > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="text-xs text-muted-foreground"
              onClick={() => {
                setStatusFilter([])
              }}
            >
              Clear all filters
            </Button>
          )}
          <div className="ml-auto">
            <DataFreshness
              dataUpdatedAt={dataUpdatedAt}
              onRefresh={() => refetch()}
              isRefreshing={isRefetching}
            />
          </div>
        </div>
      </PageSection>

      {/* Content */}
      <PageSection delay={0.1}>
        {isLoading ? (
          <SkeletonTable rows={6} />
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load teams"
            description="Something went wrong while fetching team data. Please try refreshing the page."
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Refresh
              </Button>
            }
          />
        ) : !hasAnyTeams && !search ? (
          <EmptyState
            icon={Users2}
            title="No teams yet"
            description="Teams will appear here once they are created in the system."
          />
        ) : !hasData ? (
          <EmptyState
            icon={Users2}
            variant="no-results"
            title="No results found"
            description="No teams match your current filters. Try adjusting your search or filters."
            action={
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setSearch("")
                  setStatusFilter([])
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
              <p className="text-sm text-muted-foreground">
                {filteredItems.length} team{filteredItems.length === 1 ? "" : "s"}
                {statusFilter.length > 0 && " (filtered)"}
                {data && data.total > pageSize && (
                  <span>
                    {" "}
                    &middot; Page {page} of {totalPages}
                  </span>
                )}
              </p>
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
              <Table aria-label="Teams">
                <TableHeader className="sticky top-0 z-10 bg-background">
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all teams"
                      />
                    </TableHead>
                    <SortableHeader
                      label="Team"
                      sortKey="name"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Slug"
                      sortKey="slug"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden md:table-cell"
                    />
                    <SortableHeader
                      label="Members"
                      sortKey="member_count"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Status"
                      sortKey="is_active"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden md:table-cell"
                    />
                    <SortableHeader
                      label="Created"
                      sortKey="created_at"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden lg:table-cell"
                    />
                    <TableHead className="w-16 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredItems.map((team, index) => (
                    <TeamRow
                      key={team.id}
                      team={team}
                      index={index}
                      selected={selectedIds.has(team.id)}
                      onToggle={() => toggleOne(team.id)}
                      onRowClick={() => handleRowClick(team.id)}
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
                    onClick={() => {
                      setPage((p) => Math.max(1, p - 1))
                      setSelectedIds(new Set())
                    }}
                    disabled={page <= 1}
                  >
                    Previous
                    <kbd className="ml-1.5 hidden rounded border border-border bg-muted px-1 py-0.5 text-[10px] font-medium text-muted-foreground lg:inline">&larr;</kbd>
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setPage((p) => Math.min(totalPages, p + 1))
                      setSelectedIds(new Set())
                    }}
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

function TeamRow({
  team,
  index,
  selected,
  onToggle,
  onRowClick,
}: {
  team: AdminTeamSummary
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
}) {
  const [editOpen, setEditOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)

  return (
    <>
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
            aria-label={`Select ${team.name}`}
          />
        </TableCell>
        <TableCell>
          <Link
            to="/admin/teams/$teamId"
            params={{ teamId: team.id }}
            className="group flex items-center gap-3"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary/10 text-primary">
              <Users className="h-4 w-4" />
            </div>
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="font-medium truncate group-hover:underline" title={team.name}>
                  {team.name}
                </span>
              </TooltipTrigger>
              <TooltipContent>{team.name}</TooltipContent>
            </Tooltip>
          </Link>
        </TableCell>
        <TableCell className="hidden md:table-cell">
          <span className="text-sm text-muted-foreground">{team.slug}</span>
        </TableCell>
        <TableCell>
          <Badge variant="outline" className="gap-1 tabular-nums">
            <Users className="h-3 w-3" />
            {formatMemberCount(team.memberCount)}
          </Badge>
        </TableCell>
        <TableCell className="hidden md:table-cell">
          <ActiveStatusIndicator isActive={team.isActive} />
        </TableCell>
        <TableCell className="hidden lg:table-cell">
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="cursor-default text-xs text-muted-foreground">
                {formatRelativeTimeShort(team.createdAt)}
              </span>
            </TooltipTrigger>
            <TooltipContent>{formatDateTime(team.createdAt)}</TooltipContent>
          </Tooltip>
        </TableCell>
        <TableCell className="text-right">
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
                <span className="sr-only">Actions for {team.name}</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem asChild>
                <Link to="/admin/teams/$teamId" params={{ teamId: team.id }}>
                  <Eye className="mr-2 h-4 w-4" />
                  View details
                </Link>
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => setEditOpen(true)}>
                <Pencil className="mr-2 h-4 w-4" />
                Edit team
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem className="text-destructive" onSelect={() => setDeleteOpen(true)}>
                <Trash2 className="mr-2 h-4 w-4" />
                Delete team
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </TableCell>
      </TableRow>

      <EditTeamDialog
        teamId={team.id}
        currentName={team.name}
        currentDescription={null}
        currentIsActive={team.isActive}
        open={editOpen}
        onOpenChange={setEditOpen}
      />
      <DeleteTeamDialog teamId={team.id} teamName={team.name} open={deleteOpen} onOpenChange={setDeleteOpen} />
    </>
  )
}
