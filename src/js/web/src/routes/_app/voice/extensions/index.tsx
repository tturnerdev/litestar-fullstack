import { createFileRoute, Link } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import {
  AlertCircle,
  BellOff,
  Download,
  Home,
  Loader2,
  Phone,
  PhoneForwarded,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldOff,
  X,
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
import { DataFreshness } from "@/components/ui/data-freshness"
import { Badge } from "@/components/ui/badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { BulkActionBar, createBulkDeleteAction, createBulkToggleActions, createExportAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton, SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { CreateExtensionDialog } from "@/components/voice/create-extension-dialog"
import { ExtensionRowActions } from "@/components/voice/extension-row-actions"
import {
  type Extension,
  useDeleteExtension,
  useExtensions,
  usePhoneNumbers,
  useSyncExtensions,
  useUpdateAnyExtension,
} from "@/lib/api/hooks/voice"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { useSettingsStore } from "@/lib/settings-store"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/voice/extensions/")({
  validateSearch: (
    search: Record<string, unknown>,
  ): {
    q?: string
    page?: number
    status?: string
    sort?: string
    order?: string
  } => ({
    q: typeof search.q === "string" && search.q ? search.q : undefined,
    page: Number(search.page) > 1 ? Number(search.page) : undefined,
    status: typeof search.status === "string" && search.status ? search.status : undefined,
    sort: typeof search.sort === "string" && search.sort ? search.sort : undefined,
    order:
      typeof search.order === "string" && (search.order === "asc" || search.order === "desc")
        ? search.order
        : undefined,
  }),
  component: ExtensionsPage,
})

// -- Constants ----------------------------------------------------------------

const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_OPTIONS = [10, 25, 50] as const
const PAGE_SIZE_STORAGE_KEY = "extensions-page-size"
const AUTO_REFRESH_STORAGE_KEY = "extensions-auto-refresh"
const AUTO_REFRESH_INTERVAL = 30_000

function getStoredPageSize(): number {
  try {
    const stored = localStorage.getItem(PAGE_SIZE_STORAGE_KEY)
    if (stored) {
      const parsed = Number(stored)
      if ((PAGE_SIZE_OPTIONS as readonly number[]).includes(parsed)) return parsed
    }
  } catch {
    // localStorage unavailable
  }
  return DEFAULT_PAGE_SIZE
}

const statusOptions: FilterOption[] = [
  { value: "active", label: "Active" },
  { value: "inactive", label: "Inactive" },
]

const csvHeaders: CsvHeader<Extension>[] = [
  { label: "Extension", accessor: (e) => e.extensionNumber },
  { label: "Display Name", accessor: (e) => e.displayName ?? "" },
  { label: "Phone Number Assigned", accessor: (e) => (e.phoneNumberId ? "Yes" : "No") },
  { label: "Active", accessor: (e) => (e.isActive ? "Yes" : "No") },
  { label: "DND", accessor: (e) => (e.dndEnabled ? "Yes" : "No") },
  { label: "E911 Status", accessor: (e) => e.e911Status ?? "None" },
  { label: "Forwarding", accessor: (e) => (e.forwardAlwaysEnabled ? "Always" : "No") },
]

// -- Helpers ------------------------------------------------------------------

function StatusDot({ active }: { active: boolean }) {
  return (
    <span className="flex items-center gap-1.5 text-xs">
      <span
        className={`h-2 w-2 rounded-full ${active ? "bg-emerald-500" : "bg-muted-foreground/40"}`}
      />
      <span className={active ? "text-emerald-600 dark:text-emerald-400" : "text-muted-foreground"}>
        {active ? "Active" : "Inactive"}
      </span>
    </span>
  )
}

function FeatureIndicators({ ext }: { ext: Extension }) {
  const hasE911 = ext.e911RegistrationId != null
  const e911Status = ext.e911Status ?? "none"
  const dndOn = ext.dndEnabled === true
  const fwdOn = ext.forwardAlwaysEnabled === true

  // No features worth showing
  if (!hasE911 && !dndOn && !fwdOn) return <span className="text-xs text-muted-foreground">--</span>

  return (
    <span className="flex items-center gap-1.5">
      {hasE911 && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge
              variant={e911Status === "registered" ? "default" : "outline"}
              className={`gap-1 px-1.5 py-0 text-[10px] ${e911Status === "registered" ? "bg-emerald-600 text-white" : ""}`}
            >
              {e911Status === "registered" ? (
                <Shield className="h-3 w-3" />
              ) : (
                <ShieldOff className="h-3 w-3" />
              )}
              E911
            </Badge>
          </TooltipTrigger>
          <TooltipContent>
            {e911Status === "registered" ? "E911 registered" : `E911: ${e911Status}`}
          </TooltipContent>
        </Tooltip>
      )}
      {dndOn && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="destructive" className="gap-1 px-1.5 py-0 text-[10px]">
              <BellOff className="h-3 w-3" />
              DND
            </Badge>
          </TooltipTrigger>
          <TooltipContent>Do Not Disturb is active</TooltipContent>
        </Tooltip>
      )}
      {fwdOn && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="secondary" className="gap-1 px-1.5 py-0 text-[10px]">
              <PhoneForwarded className="h-3 w-3" />
              FWD
            </Badge>
          </TooltipTrigger>
          <TooltipContent>
            Call forwarding always enabled
            {ext.forwardAlwaysDestination ? ` to ${ext.forwardAlwaysDestination}` : ""}
          </TooltipContent>
        </Tooltip>
      )}
    </span>
  )
}

// -- Main page ----------------------------------------------------------------

function ExtensionsPage() {
  useDocumentTitle("Extensions")
  const compactMode = useSettingsStore((s) => s.compactMode)
  const cellClass = compactMode ? "py-1 px-2 text-xs" : ""
  const {
    q: searchParam,
    page: pageParam,
    status: statusParam,
    sort: sortParam,
    order: orderParam,
  } = Route.useSearch()
  const navigate = Route.useNavigate()
  const searchInputRef = useRef<HTMLInputElement>(null)

  // Auto-refresh state
  const [autoRefresh, setAutoRefresh] = useState(() => {
    try {
      return localStorage.getItem(AUTO_REFRESH_STORAGE_KEY) === "true"
    } catch {
      return false
    }
  })

  const toggleAutoRefresh = useCallback(() => {
    setAutoRefresh((prev) => {
      const next = !prev
      try {
        localStorage.setItem(AUTO_REFRESH_STORAGE_KEY, String(next))
      } catch {
        // localStorage unavailable
      }
      return next
    })
  }, [])

  // Derive filter state from URL search params
  const search = searchParam ?? ""
  const page = pageParam ?? 1
  const statusFilter = useMemo(
    () => (statusParam ? statusParam.split(",").filter(Boolean) : []),
    [statusParam],
  )
  const sortKey = sortParam ?? null
  const sortDir: SortDirection = (orderParam as SortDirection) ?? null

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

  const [pageSize, setPageSize] = useState(getStoredPageSize)

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  // Sync dialog state
  const [showSyncDialog, setShowSyncDialog] = useState(false)

  // Queries & mutations
  const { data, isLoading, isError, refetch, dataUpdatedAt, isRefetching } = useExtensions(page, pageSize, autoRefresh ? AUTO_REFRESH_INTERVAL : false)
  const { data: phoneData } = usePhoneNumbers(1, 100)
  const deleteExtension = useDeleteExtension()
  const updateAnyExtension = useUpdateAnyExtension()
  const syncExtensions = useSyncExtensions()

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
          (ext.displayName ?? "").toLowerCase().includes(q) ||
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
            aVal = (a.displayName ?? "").toLowerCase()
            bVal = (b.displayName ?? "").toLowerCase()
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

  // Extension summary stats (computed from ALL items on the current page)
  const extensionStats = useMemo(() => {
    const items = data?.items ?? []
    let active = 0
    let inactive = 0
    let dnd = 0
    let forwarding = 0
    for (const ext of items) {
      if (ext.isActive) active++
      else inactive++
      if (ext.dndEnabled) dnd++
      if (ext.forwardAlwaysEnabled) forwarding++
    }
    return { active, inactive, dnd, forwarding, total: data?.total ?? 0 }
  }, [data?.items, data?.total])

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

  // Persist page size preference
  const handlePageSizeChange = useCallback(
    (value: string) => {
      const newSize = Number.parseInt(value, 10)
      setPageSize(newSize)
      navigate({ search: (prev) => ({ ...prev, page: undefined }), replace: true })
      try {
        localStorage.setItem(PAGE_SIZE_STORAGE_KEY, value)
      } catch {
        // localStorage unavailable
      }
    },
    [navigate],
  )

  // Bulk actions
  const [bulkEnableAction, bulkDisableAction] = useMemo(
    () =>
      createBulkToggleActions(
        (id, enabled) =>
          updateAnyExtension.mutateAsync({ extensionId: id, payload: { isActive: enabled } }).then(() => {}),
        () => {},
        { entityName: "extension" },
      ),
    [updateAnyExtension],
  )

  const bulkActions = useMemo(
    () => [
      bulkEnableAction,
      bulkDisableAction,
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
    [bulkEnableAction, bulkDisableAction, deleteExtension, filteredItems],
  )

  // Export all visible
  const handleExportAll = useCallback(() => {
    if (!filteredItems.length) return
    exportToCsv("extensions", csvHeaders, filteredItems)
  }, [filteredItems])

  // Active filter count for display
  const activeFilterCount = statusFilter.length

  const hasData = filteredItems.length > 0
  const hasAnyExtensions = (data?.items.length ?? 0) > 0
  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / pageSize))

  // Keyboard shortcuts: "/" to focus search, ArrowLeft/ArrowRight for pagination
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return
      if (e.key === "/" && !e.ctrlKey && !e.metaKey) {
        e.preventDefault()
        searchInputRef.current?.focus()
      }
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

  // "Go to page" input state — kept in sync with the current page
  const [pageInput, setPageInput] = useState(String(page))

  useEffect(() => {
    setPageInput(String(page))
  }, [page])

  const goToPage = useCallback(() => {
    const parsed = Number.parseInt(pageInput, 10)
    if (Number.isNaN(parsed) || parsed < 1) {
      navigate({ search: (prev) => ({ ...prev, page: undefined }), replace: true })
      setPageInput("1")
    } else if (parsed > totalPages) {
      navigate({ search: (prev) => ({ ...prev, page: totalPages > 1 ? totalPages : undefined }), replace: true })
      setPageInput(String(totalPages))
    } else {
      navigate({ search: (prev) => ({ ...prev, page: parsed > 1 ? parsed : undefined }), replace: true })
    }
  }, [pageInput, totalPages, navigate])

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
          <div className="flex items-center gap-2">
            <DataFreshness
              dataUpdatedAt={dataUpdatedAt}
              onRefresh={() => refetch()}
              isRefreshing={isRefetching}
            />
            <Button
              variant={autoRefresh ? "default" : "outline"}
              size="sm"
              onClick={toggleAutoRefresh}
            >
              {autoRefresh && (
                <span className="mr-2 h-2 w-2 animate-pulse rounded-full bg-emerald-500" />
              )}
              Live
            </Button>
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!hasData}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowSyncDialog(true)}
              disabled={syncExtensions.isPending}
            >
              {syncExtensions.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="mr-2 h-4 w-4" />
              )}
              Sync from PBX
            </Button>
            <CreateExtensionDialog
              trigger={
                <Button size="sm">
                  <Plus className="mr-2 h-4 w-4" />
                  Add Extension
                </Button>
              }
            />
          </div>
        }
      />

      {/* Summary stats */}
      <SectionErrorBoundary name="Extensions Summary">
      <div className="flex flex-wrap items-center gap-2">
        {isLoading ? (
          <>
            <Skeleton className="h-7 w-24 rounded-full" />
            <Skeleton className="h-7 w-24 rounded-full" />
            <Skeleton className="h-7 w-24 rounded-full" />
            <Skeleton className="h-7 w-28 rounded-full" />
            <Skeleton className="h-7 w-28 rounded-full" />
          </>
        ) : (
          <>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-muted/50 px-3 py-1 text-xs font-medium text-muted-foreground">
              Total
              <span className="ml-0.5 font-semibold text-foreground">{extensionStats.total}</span>
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
              Active
              <span className="ml-0.5 font-semibold">{extensionStats.active}</span>
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-zinc-400/30 bg-zinc-400/10 px-3 py-1 text-xs font-medium text-zinc-600 dark:text-zinc-400">
              <span className="h-1.5 w-1.5 rounded-full bg-zinc-400" />
              Inactive
              <span className="ml-0.5 font-semibold">{extensionStats.inactive}</span>
            </span>
            {extensionStats.dnd > 0 && (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-red-500/30 bg-red-500/10 px-3 py-1 text-xs font-medium text-red-700 dark:text-red-400">
                <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
                DND
                <span className="ml-0.5 font-semibold">{extensionStats.dnd}</span>
              </span>
            )}
            {extensionStats.forwarding > 0 && (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 px-3 py-1 text-xs font-medium text-blue-700 dark:text-blue-400">
                <span className="h-1.5 w-1.5 rounded-full bg-blue-500" />
                Forwarding
                <span className="ml-0.5 font-semibold">{extensionStats.forwarding}</span>
              </span>
            )}
          </>
        )}
      </div>
      </SectionErrorBoundary>

      {/* Search & filters */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              ref={searchInputRef}
              placeholder="Search by extension, name, or phone number..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              className="pl-9 pr-8"
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
              <kbd className="pointer-events-none absolute right-8 top-1/2 -translate-y-1/2 hidden rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground sm:inline">/</kbd>
            )}
          </div>
          <FilterDropdown
            label="Status"
            options={statusOptions}
            selected={statusFilter}
            onChange={(v) => {
              navigate({
                search: (prev) => ({
                  ...prev,
                  status: v.length > 0 ? v.join(",") : undefined,
                  page: undefined,
                }),
              })
            }}
          />
          {activeFilterCount > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="text-xs text-muted-foreground"
              onClick={() => {
                navigate({
                  search: (prev) => ({
                    ...prev,
                    status: undefined,
                    page: undefined,
                  }),
                })
              }}
            >
              Clear all filters
            </Button>
          )}
        </div>
      </PageSection>

      {/* Content */}
      <PageSection delay={0.1}>
        <SectionErrorBoundary name="Extensions Table">
        {isLoading ? (
          <SkeletonTable rows={6} />
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load extensions"
            description="Something went wrong while fetching your extensions. Please try again."
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Try again
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
                  setSearchInput("")
                  navigate({
                    search: {
                      q: undefined,
                      status: undefined,
                      sort: undefined,
                      order: undefined,
                      page: undefined,
                    },
                  })
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
                {data?.total ?? filteredItems.length} extension{(data?.total ?? filteredItems.length) === 1 ? "" : "s"}
                {statusFilter.length > 0 && " (filtered)"}
              </p>
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
              <Table aria-label="Extensions" aria-busy={isLoading || isRefetching}>
                <TableHeader className="sticky top-0 z-10 bg-background">
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
                      label="Phone Number"
                      sortKey="phone_number"
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
                    <TableHead className="hidden lg:table-cell">Features</TableHead>
                    <TableHead className="hidden md:table-cell">Created</TableHead>
                    <TableHead className="w-10">
                      <span className="sr-only">Actions</span>
                    </TableHead>
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
                      cellClass={cellClass}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className="sr-only" aria-live="polite" aria-atomic="true">
              {!isLoading && `Showing ${filteredItems.length} of ${data?.total ?? filteredItems.length} results, page ${page}`}
            </div>

            {/* Pagination */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">Rows per page</span>
                <Select value={String(pageSize)} onValueChange={handlePageSizeChange}>
                  <SelectTrigger className="h-8 w-[70px]" aria-label="Rows per page">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {PAGE_SIZE_OPTIONS.map((size) => (
                      <SelectItem key={size} value={String(size)}>
                        {size}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="flex items-center gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-sm text-muted-foreground">Page</span>
                  <Input
                    type="number"
                    min={1}
                    max={totalPages}
                    value={pageInput}
                    onChange={(e) => setPageInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") goToPage()
                    }}
                    onBlur={goToPage}
                    className="h-8 w-16 text-center"
                    aria-label="Go to page"
                  />
                  <span className="text-sm text-muted-foreground">of {totalPages}</span>
                </div>
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
            </div>
          </div>
        )}
        </SectionErrorBoundary>
      </PageSection>

      {/* Bulk action bar */}
      <BulkActionBar
        selectedCount={selectedIds.size}
        selectedIds={Array.from(selectedIds)}
        onClearSelection={() => setSelectedIds(new Set())}
        actions={bulkActions}
      />

      {/* PBX sync confirmation dialog */}
      <AlertDialog open={showSyncDialog} onOpenChange={setShowSyncDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Sync Extensions from PBX</AlertDialogTitle>
            <AlertDialogDescription>
              This will import all extensions from the connected PBX server. Existing
              extensions will be updated to match PBX data. New extensions found on
              the PBX will be created in the portal.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => syncExtensions.mutate()}>
              Sync Now
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
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
  cellClass,
}: {
  ext: Extension
  phoneNumber: string | undefined
  selected: boolean
  onToggle: () => void
  onNavigate: () => void
  cellClass: string
}) {
  return (
    <TableRow
      className="cursor-pointer hover:bg-muted/50 transition-colors"
      data-state={selected ? "selected" : undefined}
      onClick={(e) => {
        const target = e.target as HTMLElement
        if (target.closest("[role=checkbox]") || target.closest("[data-slot=dropdown]") || target.closest("button") || target.closest("a")) {
          return
        }
        onNavigate()
      }}
    >
      <TableCell className={cellClass}>
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
      <TableCell className={cellClass}>
        <Link
          to="/voice/extensions/$extensionId"
          params={{ extensionId: ext.id }}
          className="group flex flex-col gap-0.5"
          onClick={(e) => e.stopPropagation()}
        >
          <span className="font-mono font-medium group-hover:underline">{ext.extensionNumber}</span>
          {ext.displayName && (
            <span className="text-xs text-muted-foreground">{ext.displayName}</span>
          )}
        </Link>
      </TableCell>
      <TableCell className={cn("hidden md:table-cell", cellClass)}>
        {phoneNumber ? (
          <span className="font-mono text-xs">{phoneNumber}</span>
        ) : (
          <span className="text-xs text-muted-foreground">--</span>
        )}
      </TableCell>
      <TableCell className={cellClass}>
        <StatusDot active={ext.isActive ?? false} />
      </TableCell>
      <TableCell className={cn("hidden lg:table-cell", cellClass)}>
        <FeatureIndicators ext={ext} />
      </TableCell>
      <TableCell className={cn("hidden md:table-cell", cellClass)}>
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-default text-xs text-muted-foreground">
              {formatRelativeTimeShort(ext.createdAt)}
            </span>
          </TooltipTrigger>
          <TooltipContent>
            {formatDateTime(ext.createdAt)}
          </TooltipContent>
        </Tooltip>
      </TableCell>
      <TableCell className={cellClass}>
        <div onClick={(e) => e.stopPropagation()}>
          <ExtensionRowActions extension={ext} />
        </div>
      </TableCell>
    </TableRow>
  )
}
