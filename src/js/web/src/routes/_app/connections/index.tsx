import { createFileRoute, Link } from "@tanstack/react-router"
import { useCallback, useMemo, useState } from "react"
import {
  AlertCircle,
  Cable,
  CheckCircle2,
  Circle,
  Loader2,
  Plus,
  Search,
  Zap,
  XCircle,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { BulkActionBar, createBulkDeleteAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import {
  type ConnectionList,
  useConnections,
  useDeleteConnection,
  useTestAnyConnection,
} from "@/lib/api/hooks/connections"

export const Route = createFileRoute("/_app/connections/")({
  component: ConnectionsPage,
})

// ── Constants ────────────────────────────────────────────────────────────

const typeLabels: Record<string, string> = {
  pbx: "PBX",
  helpdesk: "Helpdesk",
  carrier: "Carrier",
  other: "Other",
}

const typeBadgeVariant: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
  pbx: "default",
  helpdesk: "secondary",
  carrier: "outline",
  other: "outline",
}

const connectionTypeOptions: FilterOption[] = [
  { value: "pbx", label: "PBX" },
  { value: "helpdesk", label: "Helpdesk" },
  { value: "carrier", label: "Carrier" },
  { value: "other", label: "Other" },
]

const statusOptions: FilterOption[] = [
  { value: "connected", label: "Connected" },
  { value: "disconnected", label: "Disconnected" },
  { value: "error", label: "Error" },
]

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
  return `${diffDays}d ago`
}

// ── Per-row test button ──────────────────────────────────────────────────

function TestConnectionButton({ connectionId }: { connectionId: string }) {
  const testMutation = useTestAnyConnection()
  const isPending = testMutation.isPending && testMutation.variables === connectionId

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="h-7 gap-1.5 px-2 text-xs"
          disabled={isPending}
          onClick={(e) => {
            e.preventDefault()
            e.stopPropagation()
            testMutation.mutate(connectionId)
          }}
        >
          {isPending ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Zap className="h-3.5 w-3.5" />
          )}
          Test
        </Button>
      </TooltipTrigger>
      <TooltipContent>Test this connection</TooltipContent>
    </Tooltip>
  )
}

// ── Main page ────────────────────────────────────────────────────────────

function ConnectionsPage() {
  // Filter & search state
  const [search, setSearch] = useState("")
  const [typeFilter, setTypeFilter] = useState<string[]>([])
  const [statusFilter, setStatusFilter] = useState<string[]>([])

  // Sort state
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  // Queries & mutations
  const { data, isLoading, isError } = useConnections({
    search: search || undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
  })
  const deleteConnection = useDeleteConnection()

  // Apply client-side type & status filters
  const filteredItems = useMemo(() => {
    if (!data?.items) return []
    return data.items.filter((conn) => {
      if (typeFilter.length > 0 && !typeFilter.includes(conn.connectionType)) return false
      if (statusFilter.length > 0 && !statusFilter.includes(conn.status)) return false
      return true
    })
  }, [data?.items, typeFilter, statusFilter])

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
      setSortKey(next.sort)
      setSortDir(next.direction)
    },
    [sortKey, sortDir],
  )

  // Bulk actions
  const bulkActions = useMemo(
    () => [
      createBulkDeleteAction(
        (id) => deleteConnection.mutateAsync(id),
        () => {
          setSelectedIds(new Set())
        },
      ),
    ],
    [deleteConnection],
  )

  // Active filter count for display
  const activeFilterCount = typeFilter.length + statusFilter.length

  const hasData = filteredItems.length > 0
  const hasAnyConnections = (data?.items.length ?? 0) > 0

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Connections"
        description="Manage external data source integrations (PBX, helpdesk, carriers, and more)."
        actions={
          <Button size="sm" asChild>
            <Link to="/connections/new">
              <Plus className="mr-2 h-4 w-4" /> Add connection
            </Link>
          </Button>
        }
      />

      {/* Search & filters */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search by name or provider..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
            />
          </div>
          <FilterDropdown
            label="Type"
            options={connectionTypeOptions}
            selected={typeFilter}
            onChange={setTypeFilter}
          />
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
                setTypeFilter([])
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
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <SkeletonCard key={i} />
            ))}
          </div>
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load connections"
            description="Something went wrong while fetching your connections. Please try refreshing the page."
            action={
              <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
                Refresh page
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
                  setSearch("")
                  setTypeFilter([])
                  setStatusFilter([])
                }}
              >
                Clear all filters
              </Button>
            }
          />
        ) : (
          <div className="space-y-3">
            {/* Result count */}
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                {filteredItems.length} connection{filteredItems.length === 1 ? "" : "s"}
                {(typeFilter.length > 0 || statusFilter.length > 0) && " (filtered)"}
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
                        aria-label="Select all connections"
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
                      sortKey="connection_type"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Status"
                      sortKey="status"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <TableHead>Host</TableHead>
                    <SortableHeader
                      label="Last Tested"
                      sortKey="last_health_check"
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
                  {filteredItems.map((conn) => (
                    <ConnectionRow
                      key={conn.id}
                      conn={conn}
                      selected={selectedIds.has(conn.id)}
                      onToggle={() => toggleOne(conn.id)}
                    />
                  ))}
                </TableBody>
              </Table>
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

// ── Table row ────────────────────────────────────────────────────────────

function ConnectionRow({
  conn,
  selected,
  onToggle,
}: {
  conn: ConnectionList
  selected: boolean
  onToggle: () => void
}) {
  return (
    <TableRow className="hover:bg-muted/50 transition-colors" data-state={selected ? "selected" : undefined}>
      <TableCell>
        <Checkbox
          checked={selected}
          onChange={(e) => {
            e.stopPropagation()
            onToggle()
          }}
          aria-label={`Select ${conn.name}`}
        />
      </TableCell>
      <TableCell>
        <Link
          to={`/connections/${conn.id}` as string}
          className="group flex flex-col gap-0.5"
        >
          <span className="font-medium group-hover:underline">{conn.name}</span>
          <span className="text-xs text-muted-foreground">{conn.provider}</span>
        </Link>
      </TableCell>
      <TableCell>
        <Badge variant={typeBadgeVariant[conn.connectionType] ?? "outline"}>
          {typeLabels[conn.connectionType] ?? conn.connectionType}
        </Badge>
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-2">
          <StatusIndicator status={conn.status} />
          {!conn.isEnabled && (
            <Badge variant="outline" className="border-muted-foreground/30 text-muted-foreground text-[10px]">
              Disabled
            </Badge>
          )}
        </div>
      </TableCell>
      <TableCell>
        {conn.host ? (
          <span className="font-mono text-xs text-muted-foreground">
            {conn.host}
            {conn.port ? `:${conn.port}` : ""}
          </span>
        ) : (
          <span className="text-xs text-muted-foreground">--</span>
        )}
      </TableCell>
      <TableCell>
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-default text-xs text-muted-foreground">
              {formatRelativeTime(conn.lastHealthCheck)}
            </span>
          </TooltipTrigger>
          <TooltipContent>{formatDateTime(conn.lastHealthCheck)}</TooltipContent>
        </Tooltip>
      </TableCell>
      <TableCell>
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-default text-xs text-muted-foreground">
              {formatRelativeTime(conn.createdAt)}
            </span>
          </TooltipTrigger>
          <TooltipContent>{formatDateTime(conn.createdAt)}</TooltipContent>
        </Tooltip>
      </TableCell>
      <TableCell className="text-right">
        <TestConnectionButton connectionId={conn.id} />
      </TableCell>
    </TableRow>
  )
}
