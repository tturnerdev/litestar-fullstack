import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useState } from "react"
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
  Trash2,
  X,
  Zap,
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
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
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
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"

export const Route = createFileRoute("/_app/connections/")({
  component: ConnectionsPage,
})

// ── Constants ────────────────────────────────────────────────────────────

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_STORAGE_KEY = "connections-page-size"

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
  const navigate = useNavigate()

  // Filter & search state
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [typeFilter, setTypeFilter] = useState<string[]>([])
  const [statusFilter, setStatusFilter] = useState<string[]>([])
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(getStoredPageSize)

  // Keyboard shortcut: "N" opens the create page
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "n" && !e.ctrlKey && !e.metaKey && !e.altKey) {
        const target = e.target as HTMLElement
        if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return
        e.preventDefault()
        navigate({ to: "/connections/new" })
      }
    }
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [navigate])

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
  const { data, isLoading, isError, refetch } = useConnections({
    page,
    pageSize,
    search: debouncedSearch || undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
  })
  const deleteConnection = useDeleteConnection()
  const testConnection = useTestAnyConnection()
  const [itemToDelete, setItemToDelete] = useState<{ id: string; name: string } | null>(null)

  const handleConfirmDelete = () => {
    if (itemToDelete) {
      deleteConnection.mutate(itemToDelete.id)
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
      createExportAction<ConnectionList>(
        "connections-selected",
        csvHeaders,
        (ids) => filteredItems.filter((c) => ids.includes(c.id)),
      ),
    ],
    [filteredItems, deleteConnection],
  )

  // Active filter count for display
  const activeFilterCount = typeFilter.length + statusFilter.length

  const hasData = filteredItems.length > 0
  const hasAnyConnections = (data?.items.length ?? 0) > 0
  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / pageSize))

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

      {/* Search & filters */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search by name or provider..."
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
            label="Type"
            options={connectionTypeOptions}
            selected={typeFilter}
            onChange={(v) => {
              setTypeFilter(v)
              setPage(1)
            }}
          />
          <FilterDropdown
            label="Status"
            options={statusOptions}
            selected={statusFilter}
            onChange={(v) => {
              setStatusFilter(v)
              setPage(1)
            }}
          />
          {activeFilterCount > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="text-xs text-muted-foreground"
              onClick={() => {
                setTypeFilter([])
                setStatusFilter([])
                setPage(1)
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
              <Table aria-label="Connections">
                <TableHeader className="sticky top-0 z-10 bg-background">
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
                      className="hidden md:table-cell"
                    />
                    <SortableHeader
                      label="Status"
                      sortKey="status"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <TableHead className="hidden md:table-cell">Host</TableHead>
                    <SortableHeader
                      label="Last Tested"
                      sortKey="last_health_check"
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
                      className="hidden md:table-cell"
                    />
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
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={page <= 1}
                  >
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    disabled={page >= totalPages}
                  >
                    Next
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
}: {
  conn: ConnectionList
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
  onDelete: () => void
  onTest: () => void
  isTestPending: boolean
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
          to="/connections/$connectionId"
          params={{ connectionId: conn.id }}
          className="group flex flex-col gap-0.5"
          onClick={(e) => e.stopPropagation()}
        >
          <span className="font-medium group-hover:underline">{conn.name}</span>
          <span className="text-xs text-muted-foreground">{conn.provider}</span>
        </Link>
      </TableCell>
      <TableCell className="hidden md:table-cell">
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
      <TableCell className="hidden md:table-cell">
        {conn.host ? (
          <span className="font-mono text-xs text-muted-foreground">
            {conn.host}
            {conn.port ? `:${conn.port}` : ""}
          </span>
        ) : (
          <span className="text-xs text-muted-foreground">--</span>
        )}
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-default text-xs text-muted-foreground">
              {formatRelativeTimeShort(conn.lastHealthCheck)}
            </span>
          </TooltipTrigger>
          <TooltipContent>{formatDateTime(conn.lastHealthCheck)}</TooltipContent>
        </Tooltip>
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-default text-xs text-muted-foreground">
              {formatRelativeTimeShort(conn.createdAt)}
            </span>
          </TooltipTrigger>
          <TooltipContent>{formatDateTime(conn.createdAt)}</TooltipContent>
        </Tooltip>
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
              {isTestPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Zap className="mr-2 h-4 w-4" />
              )}
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
