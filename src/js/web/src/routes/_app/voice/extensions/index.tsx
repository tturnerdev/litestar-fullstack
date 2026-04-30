import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useMemo, useState } from "react"
import {
  AlertCircle,
  CheckCircle2,
  Home,
  Phone,
  Plus,
  Search,
  X,
  XCircle,
} from "lucide-react"
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
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { CreateExtensionDialog } from "@/components/voice/create-extension-dialog"
import {
  type Extension,
  useDeleteExtension,
  useExtensions,
  usePhoneNumbers,
} from "@/lib/api/hooks/voice"
import { type CsvHeader } from "@/lib/csv-export"
import { formatRelativeTimeShort } from "@/lib/date-utils"

export const Route = createFileRoute("/_app/voice/extensions/")({
  component: ExtensionsPage,
})

// -- Constants ----------------------------------------------------------------

const statusOptions: FilterOption[] = [
  { value: "active", label: "Active" },
  { value: "inactive", label: "Inactive" },
]

const csvHeaders: CsvHeader<Extension>[] = [
  { label: "Extension", accessor: (e) => e.extensionNumber },
  { label: "Display Name", accessor: (e) => e.displayName },
  { label: "Phone Number Assigned", accessor: (e) => (e.phoneNumberId ? "Yes" : "No") },
  { label: "Active", accessor: (e) => (e.isActive ? "Yes" : "No") },
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
      <XCircle className="h-3.5 w-3.5" />
      Inactive
    </span>
  )
}

function formatDateTime(value: string | null | undefined): string {
  if (!value) return "Never"
  return new Date(value).toLocaleString()
}

// -- Main page ----------------------------------------------------------------

function ExtensionsPage() {
  const navigate = useNavigate()

  // Filter & search state
  const [search, setSearch] = useState("")
  const [statusFilter, setStatusFilter] = useState<string[]>([])

  // Sort state
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  // Queries & mutations
  const { data, isLoading, isError } = useExtensions()
  const { data: phoneData } = usePhoneNumbers(1, 100)
  const deleteExtension = useDeleteExtension()

  // Build a phone number lookup map
  const phoneMap = useMemo(() => {
    const map = new Map<string, string>()
    if (phoneData?.items) {
      for (const pn of phoneData.items) {
        map.set(pn.id, pn.number)
      }
    }
    return map
  }, [phoneData?.items])

  // Apply client-side search & status filters
  const filteredItems = useMemo(() => {
    if (!data?.items) return []
    let items = data.items

    // Status filter
    if (statusFilter.length > 0) {
      items = items.filter((ext) => {
        const status = ext.isActive ? "active" : "inactive"
        return statusFilter.includes(status)
      })
    }

    // Search filter
    if (search) {
      const q = search.toLowerCase()
      items = items.filter((ext) => {
        const phoneNumber = ext.phoneNumberId ? phoneMap.get(ext.phoneNumberId) ?? "" : ""
        return (
          ext.extensionNumber.toLowerCase().includes(q) ||
          ext.displayName.toLowerCase().includes(q) ||
          phoneNumber.toLowerCase().includes(q)
        )
      })
    }

    // Client-side sorting
    if (sortKey && sortDir) {
      const dir = sortDir === "asc" ? 1 : -1
      items = [...items].sort((a, b) => {
        let aVal: string
        let bVal: string
        switch (sortKey) {
          case "extension_number":
            aVal = a.extensionNumber
            bVal = b.extensionNumber
            break
          case "display_name":
            aVal = a.displayName.toLowerCase()
            bVal = b.displayName.toLowerCase()
            break
          case "phone_number": {
            aVal = a.phoneNumberId ? (phoneMap.get(a.phoneNumberId) ?? "") : ""
            bVal = b.phoneNumberId ? (phoneMap.get(b.phoneNumberId) ?? "") : ""
            break
          }
          case "status":
            aVal = a.isActive ? "1" : "0"
            bVal = b.isActive ? "1" : "0"
            break
          default:
            return 0
        }
        return aVal < bVal ? -dir : aVal > bVal ? dir : 0
      })
    }

    return items
  }, [data?.items, statusFilter, search, sortKey, sortDir, phoneMap])

  // Selection helpers
  const allVisibleIds = useMemo(() => filteredItems.map((e) => e.id), [filteredItems])
  const allSelected = filteredItems.length > 0 && filteredItems.every((e) => selectedIds.has(e.id))
  const someSelected = filteredItems.some((e) => selectedIds.has(e.id))

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
        (id) => deleteExtension.mutateAsync(id),
        () => {
          setSelectedIds(new Set())
        },
      ),
      createExportAction<Extension>(
        "extensions-selected",
        csvHeaders,
        (ids) => filteredItems.filter((e) => ids.includes(e.id)),
      ),
    ],
    [deleteExtension, filteredItems],
  )

  // Active filter count for display
  const activeFilterCount = statusFilter.length

  const hasData = filteredItems.length > 0
  const hasAnyExtensions = (data?.items.length ?? 0) > 0

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
            <Link to="/voice/extensions">Voice</Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          <BreadcrumbPage>Extensions</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Voice"
        title="Extensions"
        description="View and manage your extensions."
        breadcrumbs={breadcrumbs}
        actions={
          <CreateExtensionDialog
            trigger={
              <Button size="sm">
                <Plus className="mr-2 h-4 w-4" />
                Add Extension
              </Button>
            }
          />
        }
      />

      {/* Search & filters */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search by extension, name, or phone number..."
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
        </div>
      </PageSection>

      {/* Content */}
      <PageSection delay={0.1}>
        {isLoading ? (
          <SkeletonTable rows={6} />
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load extensions"
            description="Something went wrong while fetching your extensions. Please try refreshing the page."
            action={
              <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
                Refresh page
              </Button>
            }
          />
        ) : !hasAnyExtensions && !search ? (
          <EmptyState
            icon={Phone}
            title="No extensions yet"
            description="Create your first extension to get started with voice management. Extensions allow you to assign phone numbers and configure call forwarding, voicemail, and more."
            action={
              <CreateExtensionDialog
                trigger={
                  <Button size="sm">
                    <Plus className="mr-2 h-4 w-4" />
                    Add Extension
                  </Button>
                }
              />
            }
          />
        ) : !hasData ? (
          <EmptyState
            icon={Phone}
            variant="no-results"
            title="No results found"
            description="No extensions match your current search or filters. Try adjusting your criteria."
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
            {/* Result count */}
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                {filteredItems.length} extension{filteredItems.length === 1 ? "" : "s"}
                {statusFilter.length > 0 && " (filtered)"}
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
                        aria-label="Select all extensions"
                      />
                    </TableHead>
                    <SortableHeader
                      label="Extension"
                      sortKey="extension_number"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Display Name"
                      sortKey="display_name"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Phone Number"
                      sortKey="phone_number"
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
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredItems.map((ext) => (
                    <ExtensionRow
                      key={ext.id}
                      ext={ext}
                      phoneNumber={ext.phoneNumberId ? phoneMap.get(ext.phoneNumberId) : undefined}
                      selected={selectedIds.has(ext.id)}
                      onToggle={() => toggleOne(ext.id)}
                      onNavigate={() =>
                        navigate({
                          to: "/voice/extensions/$extensionId",
                          params: { extensionId: ext.id },
                        })
                      }
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

// -- Table row ----------------------------------------------------------------

function ExtensionRow({
  ext,
  phoneNumber,
  selected,
  onToggle,
  onNavigate,
}: {
  ext: Extension
  phoneNumber: string | undefined
  selected: boolean
  onToggle: () => void
  onNavigate: () => void
}) {
  return (
    <TableRow
      className="cursor-pointer"
      data-state={selected ? "selected" : undefined}
      onClick={onNavigate}
    >
      <TableCell>
        <Checkbox
          checked={selected}
          onChange={(e) => {
            e.stopPropagation()
            onToggle()
          }}
          onClick={(e) => e.stopPropagation()}
          aria-label={`Select extension ${ext.extensionNumber}`}
        />
      </TableCell>
      <TableCell>
        <Link
          to="/voice/extensions/$extensionId"
          params={{ extensionId: ext.id }}
          className="group flex flex-col gap-0.5"
          onClick={(e) => e.stopPropagation()}
        >
          <span className="font-mono font-medium group-hover:underline">{ext.extensionNumber}</span>
        </Link>
      </TableCell>
      <TableCell>{ext.displayName}</TableCell>
      <TableCell>
        {phoneNumber ? (
          <span className="font-mono text-xs">{phoneNumber}</span>
        ) : (
          <span className="text-xs text-muted-foreground">--</span>
        )}
      </TableCell>
      <TableCell>
        <StatusIndicator isActive={ext.isActive} />
      </TableCell>
      <TableCell>
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-default text-xs text-muted-foreground">
              {formatRelativeTimeShort(
                "createdAt" in ext ? (ext as unknown as { createdAt?: string }).createdAt : undefined,
              )}
            </span>
          </TooltipTrigger>
          <TooltipContent>
            {formatDateTime(
              "createdAt" in ext ? (ext as unknown as { createdAt?: string }).createdAt : undefined,
            )}
          </TooltipContent>
        </Tooltip>
      </TableCell>
    </TableRow>
  )
}
