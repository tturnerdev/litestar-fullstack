import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useMemo, useState } from "react"
import {
  AlertCircle,
  CheckCircle2,
  Circle,
  Download,
  Eye,
  Home,
  LayoutGrid,
  List,
  Mail,
  MessageSquare,
  MoreVertical,
  Pencil,
  Plus,
  Printer,
  Search,
  Trash2,
} from "lucide-react"
import { FaxNumberCard } from "@/components/fax/fax-number-card"
import { FaxNumberEditDialog } from "@/components/fax/fax-number-edit-dialog"
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
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { type FaxNumber, useDeleteFaxNumber, useFaxNumbers } from "@/lib/api/hooks/fax"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"

export const Route = createFileRoute("/_app/fax/numbers/")({
  component: FaxNumbersPage,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZE = 25

const csvHeaders: CsvHeader<FaxNumber>[] = [
  { label: "Number", accessor: (f) => f.number },
  { label: "Label", accessor: (f) => f.label ?? "" },
  { label: "Status", accessor: (f) => (f.isActive ? "Active" : "Inactive") },
]

const statusOptions: FilterOption[] = [
  { value: "active", label: "Active" },
  { value: "inactive", label: "Inactive" },
]

// -- Helpers ------------------------------------------------------------------

function StatusIndicator({ isActive }: { isActive: boolean }) {
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
      <Circle className="h-3.5 w-3.5" />
      Inactive
    </span>
  )
}


// -- Main page ----------------------------------------------------------------

function FaxNumbersPage() {
  useDocumentTitle("Fax Numbers")
  const navigate = useNavigate()

  // View mode
  const [viewMode, setViewMode] = useState<"table" | "cards">("table")

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
  const { data, isLoading, isError, refetch } = useFaxNumbers(page, PAGE_SIZE)
  const deleteFaxNumber = useDeleteFaxNumber()

  // Apply client-side search & filters
  const filteredItems = useMemo(() => {
    if (!data?.items) return []
    let items = data.items

    // Search by number or label
    if (search) {
      const q = search.toLowerCase()
      items = items.filter(
        (n) =>
          n.number.toLowerCase().includes(q) ||
          (n.label && n.label.toLowerCase().includes(q)),
      )
    }

    // Status filter
    if (statusFilter.length > 0) {
      items = items.filter((n) => {
        const status = n.isActive ? "active" : "inactive"
        return statusFilter.includes(status)
      })
    }

    // Client-side sorting
    if (sortKey && sortDir) {
      items = [...items].sort((a, b) => {
        let cmp = 0
        switch (sortKey) {
          case "number":
            cmp = a.number.localeCompare(b.number)
            break
          case "label":
            cmp = (a.label ?? "").localeCompare(b.label ?? "")
            break
          case "is_active":
            cmp = Number(a.isActive) - Number(b.isActive)
            break
          case "created_at":
            cmp = (a.createdAt ?? "").localeCompare(b.createdAt ?? "")
            break
          default:
            break
        }
        return sortDir === "desc" ? -cmp : cmp
      })
    }

    return items
  }, [data?.items, search, statusFilter, sortKey, sortDir])

  // Selection helpers
  const allVisibleIds = useMemo(() => filteredItems.map((n) => n.id), [filteredItems])
  const allSelected = filteredItems.length > 0 && filteredItems.every((n) => selectedIds.has(n.id))
  const someSelected = filteredItems.some((n) => selectedIds.has(n.id))

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
        (id) => deleteFaxNumber.mutateAsync(id),
        () => {
          setSelectedIds(new Set())
        },
      ),
      createExportAction<FaxNumber>(
        "fax-numbers-selected",
        csvHeaders,
        (ids) => filteredItems.filter((n) => ids.includes(n.id)),
      ),
    ],
    [filteredItems, deleteFaxNumber],
  )

  // Export all visible
  const handleExportAll = useCallback(() => {
    if (!filteredItems.length) return
    exportToCsv("fax-numbers", csvHeaders, filteredItems)
  }, [filteredItems])

  // Row click handler
  const handleRowClick = useCallback(
    (faxNumberId: string) => {
      navigate({ to: "/fax/numbers/$faxNumberId", params: { faxNumberId } })
    },
    [navigate],
  )

  // Active filter count
  const activeFilterCount = statusFilter.length

  const hasData = filteredItems.length > 0
  const hasAnyNumbers = (data?.items.length ?? 0) > 0
  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE))

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
            <Link to="/fax/numbers">Fax</Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          <BreadcrumbPage>Numbers</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Communications"
        title="Fax Numbers"
        description="Manage your fax numbers and configure email delivery routes."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-3">
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!hasData}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
            <Button size="sm" asChild>
              <Link to="/fax/numbers/new">
                <Plus className="mr-2 h-4 w-4" /> New Number
              </Link>
            </Button>
            <div className="flex gap-1 rounded-lg border border-border/60 p-0.5">
              <Button
                variant={viewMode === "table" ? "default" : "ghost"}
                size="sm"
                onClick={() => setViewMode("table")}
                className="h-8 px-2"
              >
                <List className="h-4 w-4" />
              </Button>
              <Button
                variant={viewMode === "cards" ? "default" : "ghost"}
                size="sm"
                onClick={() => setViewMode("cards")}
                className="h-8 px-2"
              >
                <LayoutGrid className="h-4 w-4" />
              </Button>
            </div>
          </div>
        }
      />

      {/* Search & filters */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search by number or label..."
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
          viewMode === "table" ? (
            <div className="space-y-3">
              <div className="h-5" />
              <div className="rounded-md border border-border/60 bg-card/80 p-8">
                <div className="animate-pulse space-y-4">
                  {Array.from({ length: 5 }).map((_, i) => (
                    // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
                    <div key={`skel-row-${i}`} className="h-8 rounded bg-muted/40" />
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {Array.from({ length: 6 }).map((_, index) => (
                // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
                <SkeletonCard key={`fax-num-skeleton-${index}`} />
              ))}
            </div>
          )
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load fax numbers"
            description="Something went wrong while fetching your fax numbers. Please try again."
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Try again
              </Button>
            }
          />
        ) : !hasAnyNumbers && !search ? (
          <EmptyState
            icon={Printer}
            title="No fax numbers yet"
            description="Add your first fax number to start sending and receiving faxes. You can configure email delivery routes after adding a number."
            action={
              <Button size="sm" asChild>
                <Link to="/fax/numbers/new">
                  <Plus className="mr-2 h-4 w-4" /> New Number
                </Link>
              </Button>
            }
          />
        ) : !hasData ? (
          <EmptyState
            icon={Printer}
            variant="no-results"
            title="No results found"
            description="No fax numbers match your current search or filters. Try adjusting your criteria."
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
        ) : viewMode === "table" ? (
          <div className="space-y-3">
            {/* Result count & pagination info */}
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">
                {data?.total ?? filteredItems.length} fax number{(data?.total ?? filteredItems.length) === 1 ? "" : "s"}
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
              <Table aria-label="Fax numbers">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all fax numbers"
                      />
                    </TableHead>
                    <SortableHeader
                      label="Number"
                      sortKey="number"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Label"
                      sortKey="label"
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
                    <TableHead>Email Routes</TableHead>
                    <SortableHeader
                      label="Created"
                      sortKey="created_at"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <TableHead className="w-16 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredItems.map((faxNumber, index) => (
                    <FaxNumberRow
                      key={faxNumber.id}
                      faxNumber={faxNumber}
                      index={index}
                      selected={selectedIds.has(faxNumber.id)}
                      onToggle={() => toggleOne(faxNumber.id)}
                      onRowClick={() => handleRowClick(faxNumber.id)}
                      onDelete={() => deleteFaxNumber.mutate(faxNumber.id)}
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
        ) : (
          <div className="space-y-3">
            <p className="text-xs text-muted-foreground">
              {data?.total ?? filteredItems.length} fax number{(data?.total ?? filteredItems.length) === 1 ? "" : "s"}
              {activeFilterCount > 0 && " (filtered)"}
            </p>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {filteredItems.map((faxNumber) => (
                <FaxNumberCard key={faxNumber.id} faxNumber={faxNumber} />
              ))}
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

function FaxNumberRow({
  faxNumber,
  index,
  selected,
  onToggle,
  onRowClick,
  onDelete,
}: {
  faxNumber: FaxNumber
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
  onDelete: () => void
}) {
  const [editOpen, setEditOpen] = useState(false)

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
          aria-label={`Select ${faxNumber.number}`}
        />
      </TableCell>
      <TableCell>
        <Link
          to="/fax/numbers/$faxNumberId"
          params={{ faxNumberId: faxNumber.id }}
          className="group flex flex-col gap-0.5"
          onClick={(e) => e.stopPropagation()}
        >
          <span className="font-mono font-medium group-hover:underline">
            {faxNumber.number}
          </span>
        </Link>
      </TableCell>
      <TableCell>
        <span className="text-muted-foreground">{faxNumber.label ?? "--"}</span>
      </TableCell>
      <TableCell>
        <StatusIndicator isActive={faxNumber.isActive} />
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Mail className="h-3.5 w-3.5" />
          <span>Configured</span>
        </div>
      </TableCell>
      <TableCell>
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="text-xs text-muted-foreground">
              {formatRelativeTimeShort(faxNumber.createdAt)}
            </span>
          </TooltipTrigger>
          <TooltipContent>{formatDateTime(faxNumber.createdAt)}</TooltipContent>
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
              <span className="sr-only">Actions for {faxNumber.number}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link to="/fax/numbers/$faxNumberId" params={{ faxNumberId: faxNumber.id }}>
                <Eye className="mr-2 h-4 w-4" />
                View details
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => setEditOpen(true)}>
              <Pencil className="mr-2 h-4 w-4" />
              Edit
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <Link to="/fax/messages" search={{ number: faxNumber.number }}>
                <MessageSquare className="mr-2 h-4 w-4" />
                Messages
              </Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="text-destructive focus:text-destructive"
              onClick={onDelete}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        <FaxNumberEditDialog faxNumber={faxNumber} open={editOpen} onOpenChange={setEditOpen} />
      </TableCell>
    </TableRow>
  )
}
