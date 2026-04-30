import { createFileRoute, Link } from "@tanstack/react-router"
import { useCallback, useMemo, useState } from "react"
import {
  AlertCircle,
  Eye,
  FileText,
  Home,
  Search,
  Send,
  X,
} from "lucide-react"
import { DirectionBadge, FaxStatusBadge } from "@/components/fax/fax-status-badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Badge } from "@/components/ui/badge"
import { BulkActionBar, createBulkDeleteAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import {
  type FaxMessage,
  useDeleteFaxMessage,
  useFaxMessages,
  useFaxNumbers,
} from "@/lib/api/hooks/fax"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"

export const Route = createFileRoute("/_app/fax/messages/")({
  component: FaxMessagesPage,
})

// -- Constants ----------------------------------------------------------------

const directionOptions: FilterOption[] = [
  { value: "inbound", label: "Inbound" },
  { value: "outbound", label: "Outbound" },
]

const statusOptions: FilterOption[] = [
  { value: "received", label: "Received" },
  { value: "delivered", label: "Delivered" },
  { value: "sent", label: "Sent" },
  { value: "sending", label: "Sending" },
  { value: "queued", label: "Queued" },
  { value: "failed", label: "Failed" },
]

const PAGE_SIZE = 25

// -- Helpers ------------------------------------------------------------------


function formatPages(count: number): string {
  return `${count} pg${count === 1 ? "" : "s"}`
}

// -- Main page ----------------------------------------------------------------

function FaxMessagesPage() {
  // Filter & search state
  const [search, setSearch] = useState("")
  const [directionFilter, setDirectionFilter] = useState<string[]>([])
  const [statusFilter, setStatusFilter] = useState<string[]>([])
  const [page, setPage] = useState(1)

  // Sort state
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  // Queries & mutations
  const { data: faxNumbers } = useFaxNumbers(1, 200)
  const { data, isLoading, isError } = useFaxMessages({
    page,
    pageSize: PAGE_SIZE,
    search: search || undefined,
    direction: directionFilter.length === 1 ? directionFilter[0] : undefined,
    status: statusFilter.length === 1 ? statusFilter[0] : undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
  })
  const deleteMessage = useDeleteFaxMessage()

  // Build a fax-number lookup map
  const faxNumberMap = useMemo(() => {
    const map = new Map<string, string>()
    if (faxNumbers?.items) {
      for (const num of faxNumbers.items) {
        map.set(num.id, num.label ?? num.number)
      }
    }
    return map
  }, [faxNumbers?.items])

  // Apply client-side filters for multi-select (API only takes single values)
  const filteredItems = useMemo(() => {
    if (!data?.items) return []
    return data.items.filter((msg) => {
      if (directionFilter.length > 1 && !directionFilter.includes(msg.direction)) return false
      if (statusFilter.length > 1 && !statusFilter.includes(msg.status)) return false
      return true
    })
  }, [data?.items, directionFilter, statusFilter])

  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE))

  // Selection helpers
  const allVisibleIds = useMemo(() => filteredItems.map((m) => m.id), [filteredItems])
  const allSelected = filteredItems.length > 0 && filteredItems.every((m) => selectedIds.has(m.id))
  const someSelected = filteredItems.some((m) => selectedIds.has(m.id))

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

  // Reset filters helper
  const clearAllFilters = useCallback(() => {
    setSearch("")
    setDirectionFilter([])
    setStatusFilter([])
    setPage(1)
  }, [])

  // Bulk actions
  const bulkActions = useMemo(
    () => [
      createBulkDeleteAction(
        (id) => deleteMessage.mutateAsync(id),
        () => {
          setSelectedIds(new Set())
        },
      ),
    ],
    [deleteMessage],
  )

  // Active filter count for display
  const activeFilterCount = directionFilter.length + statusFilter.length

  const hasData = filteredItems.length > 0
  const hasAnyMessages = (data?.items.length ?? 0) > 0 || !!search || activeFilterCount > 0

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
            <Link to="/fax/messages">Fax</Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          <BreadcrumbPage>Messages</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Communications"
        title="Fax Messages"
        description="View your fax history, filter by direction and status."
        breadcrumbs={breadcrumbs}
        actions={
          <Button asChild size="sm">
            <Link to="/fax/send">
              <Send className="mr-2 h-4 w-4" /> Send Fax
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
              placeholder="Search by number, sender, or subject..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                setPage(1)
              }}
              className="pl-9 pr-8"
            />
            {search && (
              <button
                type="button"
                onClick={() => {
                  setSearch("")
                  setPage(1)
                }}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
              >
                <X className="h-3.5 w-3.5" />
                <span className="sr-only">Clear search</span>
              </button>
            )}
          </div>
          <FilterDropdown
            label="Direction"
            options={directionOptions}
            selected={directionFilter}
            onChange={(v) => {
              setDirectionFilter(v)
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
          {(activeFilterCount > 0 || search) && (
            <Button
              variant="ghost"
              size="sm"
              className="text-xs text-muted-foreground"
              onClick={clearAllFilters}
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
            title="Unable to load fax messages"
            description="Something went wrong while fetching your fax history. Please try refreshing the page."
            action={
              <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
                Refresh page
              </Button>
            }
          />
        ) : !hasAnyMessages ? (
          <EmptyState
            icon={FileText}
            title="No fax messages yet"
            description="Your fax history will appear here once you send or receive a fax."
            action={
              <Button size="sm" asChild>
                <Link to="/fax/send">
                  <Send className="mr-2 h-4 w-4" /> Send your first fax
                </Link>
              </Button>
            }
          />
        ) : !hasData ? (
          <EmptyState
            icon={FileText}
            variant="no-results"
            title="No results found"
            description="No fax messages match your current filters. Try adjusting your search or filters."
            action={
              <Button variant="outline" size="sm" onClick={clearAllFilters}>
                Clear all filters
              </Button>
            }
          />
        ) : (
          <div className="space-y-3">
            {/* Result count & pagination info */}
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                {data?.total ?? filteredItems.length} message{(data?.total ?? filteredItems.length) === 1 ? "" : "s"}
                {activeFilterCount > 0 && " (filtered)"}
              </p>
              {totalPages > 1 && (
                <p className="text-sm text-muted-foreground">
                  Page {page} of {totalPages}
                </p>
              )}
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
                        aria-label="Select all messages"
                      />
                    </TableHead>
                    <SortableHeader
                      label="Date"
                      sortKey="received_at"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Direction"
                      sortKey="direction"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Remote Number"
                      sortKey="remote_number"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <TableHead>Fax Line</TableHead>
                    <TableHead>Pages</TableHead>
                    <SortableHeader
                      label="Status"
                      sortKey="status"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <TableHead className="w-20 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredItems.map((msg) => (
                    <FaxMessageRow
                      key={msg.id}
                      msg={msg}
                      faxLineName={faxNumberMap.get(msg.faxNumberId) ?? ""}
                      selected={selectedIds.has(msg.id)}
                      onToggle={() => toggleOne(msg.id)}
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

function FaxMessageRow({
  msg,
  faxLineName,
  selected,
  onToggle,
}: {
  msg: FaxMessage
  faxLineName: string
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
          aria-label={`Select message from ${msg.remoteNumber}`}
        />
      </TableCell>
      <TableCell>
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-default whitespace-nowrap text-xs text-muted-foreground">
              {formatRelativeTimeShort(msg.receivedAt ?? msg.createdAt)}
            </span>
          </TooltipTrigger>
          <TooltipContent>{formatDateTime(msg.receivedAt ?? msg.createdAt)}</TooltipContent>
        </Tooltip>
      </TableCell>
      <TableCell>
        <DirectionBadge direction={msg.direction} />
      </TableCell>
      <TableCell>
        <div className="flex flex-col gap-0.5">
          <span className="font-mono text-sm">{msg.remoteNumber}</span>
          {msg.remoteName && (
            <span className="text-xs text-muted-foreground">{msg.remoteName}</span>
          )}
        </div>
      </TableCell>
      <TableCell>
        <span className="text-sm text-muted-foreground">{faxLineName || "--"}</span>
      </TableCell>
      <TableCell>
        <Badge variant="outline" className="font-mono text-xs">
          {formatPages(msg.pageCount)}
        </Badge>
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-2">
          <FaxStatusBadge status={msg.status} />
          {msg.errorMessage && (
            <Tooltip>
              <TooltipTrigger asChild>
                <AlertCircle className="h-3.5 w-3.5 cursor-help text-destructive" />
              </TooltipTrigger>
              <TooltipContent className="max-w-xs">{msg.errorMessage}</TooltipContent>
            </Tooltip>
          )}
        </div>
      </TableCell>
      <TableCell className="text-right">
        <Tooltip>
          <TooltipTrigger asChild>
            <Button asChild variant="ghost" size="sm" className="h-7 gap-1.5 px-2 text-xs">
              <Link to="/fax/messages/$messageId" params={{ messageId: msg.id }}>
                <Eye className="h-3.5 w-3.5" />
                View
              </Link>
            </Button>
          </TooltipTrigger>
          <TooltipContent>View fax details</TooltipContent>
        </Tooltip>
      </TableCell>
    </TableRow>
  )
}
