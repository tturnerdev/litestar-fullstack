import { createFileRoute, Link } from "@tanstack/react-router"
import { useCallback, useMemo, useState } from "react"
import {
  AlertCircle,
  CheckCircle2,
  Search,
  Trash2,
  Users,
  Users2,
  XCircle,
} from "lucide-react"
import { toast } from "sonner"
import { useQueryClient } from "@tanstack/react-query"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { TeamRowActions } from "@/components/admin/team-row-actions"
import { Badge } from "@/components/ui/badge"
import { type BulkAction, BulkActionBar } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { EmptyState } from "@/components/ui/empty-state"
import { ExportButton } from "@/components/ui/export-button"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useAdminTeams } from "@/lib/api/hooks/admin"
import { adminDeleteTeam } from "@/lib/generated/api"
import type { AdminTeamSummary } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/admin/teams/")({
  component: AdminTeamsPage,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZE = 25

const TEAM_EXPORT_COLUMNS = [
  { key: "name", header: "Name" },
  { key: "slug", header: "Slug" },
  { key: "memberCount", header: "Members" },
  { key: "isActive", header: "Active" },
  { key: "createdAt", header: "Created At" },
]

const statusOptions: FilterOption[] = [
  { value: "active", label: "Active" },
  { value: "inactive", label: "Inactive" },
]

// -- Helpers ------------------------------------------------------------------

function formatDateTime(value: string | null | undefined): string {
  if (!value) return "Never"
  return new Date(value).toLocaleString()
}

function formatRelativeTime(value: string | null | undefined): string {
  if (!value) return "Never"
  const date = new Date(value)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60_000)
  if (diffMins < 1) return "Just now"
  if (diffMins < 60) return `${diffMins}m ago`
  const diffHours = Math.floor(diffMins / 60)
  if (diffHours < 24) return `${diffHours}h ago`
  const diffDays = Math.floor(diffHours / 24)
  if (diffDays < 30) return `${diffDays}d ago`
  const diffMonths = Math.floor(diffDays / 30)
  return `${diffMonths}mo ago`
}

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
  // Filter & search state
  const [search, setSearch] = useState("")
  const [statusFilter, setStatusFilter] = useState<string[]>([])
  const [page, setPage] = useState(1)

  // Sort state
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  // Queries & mutations
  const queryClient = useQueryClient()
  const { data, isLoading, isError, refetch } = useAdminTeams({
    page,
    pageSize: PAGE_SIZE,
    search: search || undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
  })

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

  // Computed
  const activeFilterCount = statusFilter.length
  const hasData = filteredItems.length > 0
  const hasAnyTeams = (data?.items.length ?? 0) > 0
  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE))

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Teams"
        description="View and manage all teams in the system."
        breadcrumbs={<AdminBreadcrumbs />}
        actions={
          <ExportButton
            data={(data?.items ?? []) as Record<string, unknown>[]}
            filename="teams"
            columns={TEAM_EXPORT_COLUMNS}
          />
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
              onChange={(e) => {
                setSearch(e.target.value)
                setPage(1)
              }}
              className="pl-9"
            />
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
                {data && data.total > PAGE_SIZE && (
                  <span>
                    {" "}
                    &middot; Page {page} of {totalPages}
                  </span>
                )}
              </p>
            </div>

            {/* Table */}
            <div className="rounded-md border border-border/60 bg-card/80">
              <Table>
                <TableHeader>
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
                    />
                    <SortableHeader
                      label="Created"
                      sortKey="created_at"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <TableHead className="w-20 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredItems.map((team) => (
                    <TeamRow
                      key={team.id}
                      team={team}
                      selected={selectedIds.has(team.id)}
                      onToggle={() => toggleOne(team.id)}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-end gap-2">
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
                </Button>
              </div>
            )}
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
  selected,
  onToggle,
}: {
  team: AdminTeamSummary
  selected: boolean
  onToggle: () => void
}) {
  return (
    <TableRow data-state={selected ? "selected" : undefined}>
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
        >
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary/10 text-primary">
            <Users className="h-4 w-4" />
          </div>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="font-medium truncate group-hover:underline">
                {team.name}
              </span>
            </TooltipTrigger>
            <TooltipContent>{team.name}</TooltipContent>
          </Tooltip>
        </Link>
      </TableCell>
      <TableCell>
        <span className="text-sm text-muted-foreground">{team.slug}</span>
      </TableCell>
      <TableCell>
        <Badge variant="outline" className="gap-1 tabular-nums">
          <Users className="h-3 w-3" />
          {formatMemberCount(team.memberCount)}
        </Badge>
      </TableCell>
      <TableCell>
        <ActiveStatusIndicator isActive={team.isActive} />
      </TableCell>
      <TableCell>
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-default text-xs text-muted-foreground">
              {formatRelativeTime(team.createdAt)}
            </span>
          </TooltipTrigger>
          <TooltipContent>{formatDateTime(team.createdAt)}</TooltipContent>
        </Tooltip>
      </TableCell>
      <TableCell className="text-right">
        <TeamRowActions team={team} />
      </TableCell>
    </TableRow>
  )
}
