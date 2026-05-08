import { createFileRoute, Link } from "@tanstack/react-router"
import { AlertCircle, AlertTriangle, Bell, BellOff, Copy, Download, Eye, Loader2, Mail, MailPlus, MoreVertical, Pencil, Search, SlidersHorizontal, Trash2, X } from "lucide-react"
import { useCallback, useEffect, useMemo, useState } from "react"
import { toast } from "sonner"
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
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { BulkActionBar, createBulkDeleteAction, createExportAction } from "@/components/ui/bulk-action-bar"
import { Button, buttonVariants } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { CopyButton } from "@/components/ui/copy-button"
import { DataFreshness } from "@/components/ui/data-freshness"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { type FaxEmailRouteWithNumber, useAllFaxEmailRoutes, useCreateFaxEmailRoute, useDeleteFaxEmailRoute, useFaxNumbers, useUpdateFaxEmailRoute } from "@/lib/api/hooks/fax"
import { type CsvHeader, exportToCsv } from "@/lib/csv-export"
import { formatDateTime } from "@/lib/date-utils"
import { client } from "@/lib/generated/api/client.gen"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/fax/email-routes")({
  validateSearch: (
    search: Record<string, unknown>,
  ): {
    q?: string
  } => ({
    q: typeof search.q === "string" && search.q ? search.q : undefined,
  }),
  component: FaxEmailRoutesPage,
})

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

// ---------------------------------------------------------------------------
// CSV Headers
// ---------------------------------------------------------------------------

const csvHeaders: CsvHeader<FaxEmailRouteWithNumber>[] = [
  { label: "Email Address", accessor: (r) => r.emailAddress },
  { label: "Fax Number", accessor: (r) => r.faxNumber },
  { label: "Fax Number Label", accessor: (r) => r.faxNumberLabel ?? "" },
  { label: "Status", accessor: (r) => (r.isActive ? "Active" : "Inactive") },
  { label: "Failure Alerts", accessor: (r) => (r.notifyOnFailure ? "On" : "Off") },
  { label: "Created", accessor: (r) => formatDateTime(r.createdAt, "") },
]

const statusFilterOptions: FilterOption[] = [
  { value: "active", label: "Active" },
  { value: "inactive", label: "Inactive" },
]

// ---------------------------------------------------------------------------
// Column visibility
// ---------------------------------------------------------------------------

const COLUMN_VISIBILITY_KEY = "fax-email-routes-columns"

const TOGGLEABLE_COLUMNS = [
  { key: "faxNumber", label: "Fax Number" },
  { key: "status", label: "Status" },
  { key: "failureAlerts", label: "Failure Alerts" },
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

// ---------------------------------------------------------------------------
// Create Dialog
// ---------------------------------------------------------------------------

function CreateEmailRouteDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { data: numbers } = useFaxNumbers(1, 200)
  const [faxNumberId, setFaxNumberId] = useState("")
  const [emailAddress, setEmailAddress] = useState("")
  const [isActive, setIsActive] = useState(true)
  const [notifyOnFailure, setNotifyOnFailure] = useState(true)
  const [errors, setErrors] = useState<Record<string, string>>({})

  const createMutation = useCreateFaxEmailRoute(faxNumberId)

  function resetForm() {
    setFaxNumberId("")
    setEmailAddress("")
    setIsActive(true)
    setNotifyOnFailure(true)
    setErrors({})
  }

  function handleSubmit() {
    const fieldErrors: Record<string, string> = {}
    if (!faxNumberId) {
      fieldErrors.faxNumberId = "Please select a fax number"
    }
    const trimmed = emailAddress.trim()
    if (!trimmed) {
      fieldErrors.emailAddress = "This field is required"
    } else if (!EMAIL_REGEX.test(trimmed)) {
      fieldErrors.emailAddress = "Please enter a valid email address"
    }
    setErrors(fieldErrors)
    if (Object.keys(fieldErrors).length > 0) return
    createMutation.mutate(
      { emailAddress: trimmed, isActive, notifyOnFailure },
      {
        onSuccess: () => {
          toast.success("Email route created")
          resetForm()
          onOpenChange(false)
        },
        onError: (err) => {
          toast.error("Failed to create email route", {
            description: err instanceof Error ? err.message : undefined,
          })
        },
      },
    )
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        if (!v) resetForm()
        onOpenChange(v)
      }}
    >
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>New Email Route</DialogTitle>
          <DialogDescription>Route incoming faxes to an email address.</DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <Label htmlFor="create-fax-number">Fax Number</Label>
            <Select
              value={faxNumberId}
              onValueChange={(v) => {
                setFaxNumberId(v)
                if (errors.faxNumberId) setErrors((prev) => ({ ...prev, faxNumberId: "" }))
              }}
            >
              <SelectTrigger id="create-fax-number" aria-invalid={!!errors.faxNumberId}>
                <SelectValue placeholder="Select a fax number" />
              </SelectTrigger>
              <SelectContent>
                {numbers?.items?.map((n) => (
                  <SelectItem key={n.id} value={n.id}>
                    {n.number}
                    {n.label ? ` (${n.label})` : ""}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errors.faxNumberId && <p className="text-xs text-destructive">{errors.faxNumberId}</p>}
          </div>
          <div className="space-y-2">
            <Label htmlFor="create-email">Email Address</Label>
            <Input
              id="create-email"
              type="email"
              placeholder="user@example.com"
              value={emailAddress}
              onChange={(e) => {
                setEmailAddress(e.target.value)
                if (errors.emailAddress) setErrors((prev) => ({ ...prev, emailAddress: "" }))
              }}
              onBlur={() => {
                const trimmed = emailAddress.trim()
                if (!trimmed) {
                  setErrors((prev) => ({ ...prev, emailAddress: "This field is required" }))
                } else if (!EMAIL_REGEX.test(trimmed)) {
                  setErrors((prev) => ({ ...prev, emailAddress: "Please enter a valid email address" }))
                }
              }}
              onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
              aria-invalid={!!errors.emailAddress}
            />
            {errors.emailAddress && <p className="text-xs text-destructive">{errors.emailAddress}</p>}
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="create-active">Active</Label>
            <Switch id="create-active" checked={isActive} onCheckedChange={setIsActive} />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="create-notify">Notify on Failure</Label>
            <Switch id="create-notify" checked={notifyOnFailure} onCheckedChange={setNotifyOnFailure} />
          </div>
        </div>
        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => {
              resetForm()
              onOpenChange(false)
            }}
            disabled={createMutation.isPending}
          >
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={createMutation.isPending || !faxNumberId || !emailAddress.trim()}>
            {createMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {createMutation.isPending ? "Creating..." : "Create Route"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Edit Dialog
// ---------------------------------------------------------------------------

function EditEmailRouteDialog({ route, onOpenChange }: { route: FaxEmailRouteWithNumber | null; onOpenChange: (open: boolean) => void }) {
  const [emailAddress, setEmailAddress] = useState(route?.emailAddress ?? "")
  const [isActive, setIsActive] = useState(route?.isActive ?? true)
  const [notifyOnFailure, setNotifyOnFailure] = useState(route?.notifyOnFailure ?? true)
  const [errors, setErrors] = useState<Record<string, string>>({})

  const updateMutation = useUpdateFaxEmailRoute(route?.faxNumberId ?? "", route?.id ?? "")

  function handleSubmit() {
    const trimmed = emailAddress.trim()
    const fieldErrors: Record<string, string> = {}
    if (!trimmed) {
      fieldErrors.emailAddress = "This field is required"
    } else if (!EMAIL_REGEX.test(trimmed)) {
      fieldErrors.emailAddress = "Please enter a valid email address"
    }
    setErrors(fieldErrors)
    if (Object.keys(fieldErrors).length > 0) return
    if (!route) return

    const payload: Record<string, unknown> = {}
    if (trimmed !== route.emailAddress) payload.emailAddress = trimmed
    if (isActive !== route.isActive) payload.isActive = isActive
    if (notifyOnFailure !== route.notifyOnFailure) payload.notifyOnFailure = notifyOnFailure

    if (Object.keys(payload).length === 0) {
      onOpenChange(false)
      return
    }

    updateMutation.mutate(payload, {
      onSuccess: () => {
        toast.success("Email route updated")
        onOpenChange(false)
      },
      onError: (err) => {
        toast.error("Failed to update email route", {
          description: err instanceof Error ? err.message : undefined,
        })
      },
    })
  }

  // Sync form fields when route changes
  if (route && emailAddress === "" && route.emailAddress !== "") {
    setEmailAddress(route.emailAddress)
    setIsActive(route.isActive ?? false)
    setNotifyOnFailure(route.notifyOnFailure ?? true)
  }

  return (
    <Dialog open={!!route} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Edit Email Route</DialogTitle>
          <DialogDescription>
            Update the routing for <span className="font-mono text-foreground">{route?.faxNumber}</span>
            {route?.faxNumberLabel ? ` (${route.faxNumberLabel})` : ""}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <Label htmlFor="edit-email">Email Address</Label>
            <Input
              id="edit-email"
              type="email"
              placeholder="user@example.com"
              value={emailAddress}
              onChange={(e) => {
                setEmailAddress(e.target.value)
                if (errors.emailAddress) setErrors((prev) => ({ ...prev, emailAddress: "" }))
              }}
              onBlur={() => {
                const trimmed = emailAddress.trim()
                if (!trimmed) {
                  setErrors((prev) => ({ ...prev, emailAddress: "This field is required" }))
                } else if (!EMAIL_REGEX.test(trimmed)) {
                  setErrors((prev) => ({ ...prev, emailAddress: "Please enter a valid email address" }))
                }
              }}
              onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
              aria-invalid={!!errors.emailAddress}
            />
            {errors.emailAddress && <p className="text-xs text-destructive">{errors.emailAddress}</p>}
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="edit-active">Active</Label>
            <Switch id="edit-active" checked={isActive} onCheckedChange={setIsActive} />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="edit-notify">Notify on Failure</Label>
            <Switch id="edit-notify" checked={notifyOnFailure} onCheckedChange={setNotifyOnFailure} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={updateMutation.isPending}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={updateMutation.isPending}>
            {updateMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {updateMutation.isPending ? "Saving..." : "Save Changes"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Delete Dialog
// ---------------------------------------------------------------------------

function DeleteEmailRouteDialog({ route, onOpenChange }: { route: FaxEmailRouteWithNumber | null; onOpenChange: (open: boolean) => void }) {
  const deleteMutation = useDeleteFaxEmailRoute(route?.faxNumberId ?? "")

  return (
    <AlertDialog open={!!route} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            Delete Email Route
          </AlertDialogTitle>
          <AlertDialogDescription>
            Are you sure you want to remove the route for <span className="font-medium text-foreground">{route?.emailAddress}</span> on fax number{" "}
            <span className="font-mono text-foreground">{route?.faxNumber}</span>? This action cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={() => onOpenChange(false)} disabled={deleteMutation.isPending}>
            Cancel
          </AlertDialogCancel>
          <AlertDialogAction
            className={buttonVariants({ variant: "destructive" })}
            disabled={deleteMutation.isPending}
            onClick={() => {
              if (!route) return
              deleteMutation.mutate(route.id, {
                onSuccess: () => {
                  toast.success("Email route deleted")
                  onOpenChange(false)
                },
                onError: (err) => {
                  toast.error("Failed to delete email route", {
                    description: err instanceof Error ? err.message : undefined,
                  })
                },
              })
            }}
          >
            {deleteMutation.isPending ? "Deleting..." : "Delete Route"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------

function FaxEmailRoutesPage() {
  useDocumentTitle("Fax Email Routes")
  const { q: searchParam } = Route.useSearch()
  const navigate = Route.useNavigate()
  const { data: routes, isLoading, isError, refetch, dataUpdatedAt, isRefetching } = useAllFaxEmailRoutes()
  const [showCreateDialog, setShowCreateDialog] = useState(false)
  const [editRoute, setEditRoute] = useState<FaxEmailRouteWithNumber | null>(null)
  const [deleteRoute, setDeleteRoute] = useState<FaxEmailRouteWithNumber | null>(null)

  // Search & filter state
  const search = searchParam ?? ""
  const [searchInput, setSearchInput] = useState(search)
  const debouncedSearch = useDebouncedValue(searchInput)
  const [statusFilter, setStatusFilter] = useState<string[]>([])

  // Sync URL when debounced search value settles
  useEffect(() => {
    navigate({
      search: (prev) => ({
        ...prev,
        q: debouncedSearch || undefined,
      }),
      replace: true,
    })
  }, [debouncedSearch, navigate])

  // Keep local input in sync if URL search param changes externally (back/forward)
  useEffect(() => {
    setSearchInput(search)
  }, [search])

  // Sort state
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  const handleSort = useCallback(
    (key: string) => {
      const next = nextSortDirection(sortKey, sortDir, key)
      setSortKey(next.sort)
      setSortDir(next.direction)
    },
    [sortKey, sortDir],
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

  const filteredRoutes = useMemo(() => {
    if (!routes) return []
    let result = routes

    // Status filter
    if (statusFilter.length === 1) {
      const wantActive = statusFilter[0] === "active"
      result = result.filter((r) => r.isActive === wantActive)
    }

    // Text search
    if (debouncedSearch) {
      const q = debouncedSearch.toLowerCase()
      result = result.filter((route) => route.emailAddress?.toLowerCase().includes(q) || route.faxNumber?.toLowerCase().includes(q))
    }

    return result
  }, [routes, debouncedSearch, statusFilter])

  // Client-side sorting
  const sortedRoutes = useMemo(() => {
    if (!sortKey || !sortDir) return filteredRoutes
    const sorted = [...filteredRoutes]
    sorted.sort((a, b) => {
      let aVal: string | number
      let bVal: string | number
      switch (sortKey) {
        case "email":
          aVal = a.emailAddress.toLowerCase()
          bVal = b.emailAddress.toLowerCase()
          break
        case "faxNumber":
          aVal = a.faxNumber.toLowerCase()
          bVal = b.faxNumber.toLowerCase()
          break
        case "status":
          aVal = a.isActive ? 0 : 1
          bVal = b.isActive ? 0 : 1
          break
        case "created":
          aVal = a.createdAt ?? ""
          bVal = b.createdAt ?? ""
          break
        default:
          return 0
      }
      if (aVal < bVal) return sortDir === "asc" ? -1 : 1
      if (aVal > bVal) return sortDir === "asc" ? 1 : -1
      return 0
    })
    return sorted
  }, [filteredRoutes, sortKey, sortDir])

  const activeFilterCount = statusFilter.length + (debouncedSearch ? 1 : 0)

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  const allVisibleIds = useMemo(() => sortedRoutes.map((r) => r.id), [sortedRoutes])
  const allSelected = sortedRoutes.length > 0 && sortedRoutes.every((r) => selectedIds.has(r.id))
  const someSelected = sortedRoutes.some((r) => selectedIds.has(r.id))

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

  // Export all visible
  const handleExportAll = useCallback(() => {
    if (!routes?.length) return
    exportToCsv("fax-email-routes", csvHeaders, routes)
  }, [routes])

  // Bulk actions
  const bulkActions = useMemo(
    () => [
      createBulkDeleteAction(
        async (id) => {
          const route = routes?.find((r) => r.id === id)
          if (!route) return
          await client.request({
            method: "DELETE",
            url: `/api/fax/numbers/${route.faxNumberId}/email-routes/${id}`,
          })
        },
        () => {
          setSelectedIds(new Set())
        },
      ),
      createExportAction<FaxEmailRouteWithNumber>("fax-email-routes-selected", csvHeaders, (ids) => (routes ?? []).filter((r) => ids.includes(r.id))),
    ],
    [routes],
  )

  const hasData = (routes ?? []).length > 0

  const breadcrumbs = (
    <Breadcrumb>
      <BreadcrumbList>
        <BreadcrumbItem>
          <BreadcrumbLink asChild>
            <Link to="/home">Home</Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          <BreadcrumbLink asChild>
            <Link to="/fax">Fax</Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          <BreadcrumbPage>Email Routes</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Communications"
        title="Email Routes"
        description="Configure where incoming faxes are delivered via email across all fax numbers."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-3">
            <DataFreshness dataUpdatedAt={dataUpdatedAt} onRefresh={() => refetch()} isRefreshing={isRefetching} />
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
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!hasData}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
            <Button size="sm" onClick={() => setShowCreateDialog(true)}>
              <MailPlus className="mr-2 h-4 w-4" /> New Route
            </Button>
          </div>
        }
      />

      <PageSection>
        <SectionErrorBoundary name="Email Routes">
          {isLoading ? (
            <SkeletonTable rows={5} />
          ) : isError ? (
            <EmptyState
              icon={AlertCircle}
              title="Unable to load email routes"
              description="Something went wrong while fetching email routes. Please try refreshing the page."
              action={
                <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
                  Refresh page
                </Button>
              }
            />
          ) : routes && routes.length > 0 ? (
            <div className="space-y-4">
              {/* Filters */}
              <div className="flex flex-wrap items-center gap-3">
                <div className="relative max-w-sm flex-1">
                  <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    placeholder="Search by email or fax number..."
                    value={searchInput}
                    onChange={(e) => setSearchInput(e.target.value)}
                    className="pl-9 pr-9"
                    aria-label="Search email routes"
                  />
                  {searchInput && (
                    <button
                      type="button"
                      onClick={() => setSearchInput("")}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                      aria-label="Clear search"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  )}
                </div>
                <FilterDropdown label="Status" options={statusFilterOptions} selected={statusFilter} onChange={setStatusFilter} />
                {activeFilterCount > 0 && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-xs text-muted-foreground"
                    onClick={() => {
                      setSearchInput("")
                      setStatusFilter([])
                    }}
                  >
                    Clear filters
                  </Button>
                )}
                <p className="ml-auto text-sm text-muted-foreground">
                  {activeFilterCount > 0
                    ? `Showing ${sortedRoutes.length} of ${routes.length} routes`
                    : `${routes.filter((r) => r.isActive).length} of ${routes.length} routes active`}
                </p>
              </div>

              {sortedRoutes.length === 0 ? (
                <EmptyState
                  icon={Search}
                  title="No matching routes"
                  description="No email routes match your current filters. Try adjusting your search or filter criteria."
                  action={
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setSearchInput("")
                        setStatusFilter([])
                      }}
                    >
                      Clear filters
                    </Button>
                  }
                />
              ) : (
                <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
                  <Table aria-label="Email routes" aria-busy={isLoading || isRefetching}>
                    <TableHeader className="sticky top-0 z-10 bg-background">
                      <TableRow>
                        <TableHead className="w-10">
                          <Checkbox checked={allSelected} indeterminate={someSelected && !allSelected} onChange={toggleAll} aria-label="Select all email routes" />
                        </TableHead>
                        <SortableHeader label="Email Address" sortKey="email" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />
                        {isColumnVisible("faxNumber") && (
                          <SortableHeader label="Fax Number" sortKey="faxNumber" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />
                        )}
                        {isColumnVisible("status") && <SortableHeader label="Status" sortKey="status" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />}
                        {isColumnVisible("failureAlerts") && <TableHead>Failure Alerts</TableHead>}
                        {isColumnVisible("created") && <SortableHeader label="Created" sortKey="created" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />}
                        <TableHead className="w-16 text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {sortedRoutes.map((route, index) => (
                        <TableRow
                          key={route.id}
                          data-state={selectedIds.has(route.id) ? "selected" : undefined}
                          className={cn("cursor-pointer hover:bg-muted/50 transition-colors", index % 2 === 1 ? "bg-muted/20" : "")}
                          onClick={(e) => {
                            const target = e.target as HTMLElement
                            if (target.closest("[role=checkbox]") || target.closest("[data-slot=dropdown]") || target.closest("button") || target.closest("a")) {
                              return
                            }
                            setEditRoute(route)
                          }}
                        >
                          <TableCell>
                            <Checkbox
                              checked={selectedIds.has(route.id)}
                              onChange={(e) => {
                                e.stopPropagation()
                                toggleOne(route.id)
                              }}
                              aria-label={`Select route for ${route.emailAddress}`}
                            />
                          </TableCell>
                          <TableCell className="font-mono text-sm">
                            <span className="inline-flex items-center gap-1">
                              {route.emailAddress}
                              <CopyButton value={route.emailAddress} label="email address" />
                            </span>
                          </TableCell>
                          {isColumnVisible("faxNumber") && (
                            <TableCell>
                              <span className="inline-flex items-center gap-1">
                                <Link
                                  to="/fax/numbers/$faxNumberId"
                                  params={{ faxNumberId: route.faxNumberId }}
                                  className="text-sm text-primary hover:underline"
                                  onClick={(e) => e.stopPropagation()}
                                >
                                  <span className="font-mono">{route.faxNumber}</span>
                                  {route.faxNumberLabel && <span className="ml-1.5 text-muted-foreground">({route.faxNumberLabel})</span>}
                                </Link>
                                <CopyButton value={route.faxNumber} label="fax number" />
                              </span>
                            </TableCell>
                          )}
                          {isColumnVisible("status") && (
                            <TableCell>
                              <Badge variant={route.isActive ? "default" : "secondary"}>{route.isActive ? "Active" : "Inactive"}</Badge>
                            </TableCell>
                          )}
                          {isColumnVisible("failureAlerts") && (
                            <TableCell>
                              {route.notifyOnFailure ? (
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <span className="inline-flex items-center gap-1 text-sm text-emerald-600 dark:text-emerald-400">
                                      <Bell className="h-3.5 w-3.5" /> On
                                    </span>
                                  </TooltipTrigger>
                                  <TooltipContent>Failure notifications enabled</TooltipContent>
                                </Tooltip>
                              ) : (
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <span className="inline-flex items-center gap-1 text-sm text-muted-foreground">
                                      <BellOff className="h-3.5 w-3.5" /> Off
                                    </span>
                                  </TooltipTrigger>
                                  <TooltipContent>Failure notifications disabled</TooltipContent>
                                </Tooltip>
                              )}
                            </TableCell>
                          )}
                          {isColumnVisible("created") && <TableCell className="text-sm text-muted-foreground">{formatDateTime(route.createdAt, "--")}</TableCell>}
                          <TableCell className="text-right">
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="icon" className="h-8 w-8" data-slot="dropdown" onClick={(e) => e.stopPropagation()}>
                                  <MoreVertical className="h-4 w-4" />
                                  <span className="sr-only">Actions for {route.emailAddress}</span>
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end">
                                <DropdownMenuItem onClick={() => navigator.clipboard.writeText(route.id)}>
                                  <Copy className="mr-2 h-4 w-4" />
                                  Copy Route ID
                                </DropdownMenuItem>
                                <DropdownMenuItem asChild>
                                  <Link to="/fax/numbers/$faxNumberId" params={{ faxNumberId: route.faxNumberId }}>
                                    <Eye className="mr-2 h-4 w-4" />
                                    View fax number
                                  </Link>
                                </DropdownMenuItem>
                                <DropdownMenuItem onClick={() => setEditRoute(route)}>
                                  <Pencil className="mr-2 h-4 w-4" />
                                  Edit
                                </DropdownMenuItem>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem className="text-destructive focus:text-destructive" onClick={() => setDeleteRoute(route)}>
                                  <Trash2 className="mr-2 h-4 w-4" />
                                  Delete
                                </DropdownMenuItem>
                              </DropdownMenuContent>
                            </DropdownMenu>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </div>
          ) : (
            <EmptyState
              icon={Mail}
              title="No email routes configured"
              description="Email routes deliver incoming faxes to an email address. Add your first route to get started."
              action={
                <Button size="sm" onClick={() => setShowCreateDialog(true)}>
                  <MailPlus className="mr-2 h-4 w-4" /> New Route
                </Button>
              }
            />
          )}
        </SectionErrorBoundary>
      </PageSection>

      <CreateEmailRouteDialog open={showCreateDialog} onOpenChange={setShowCreateDialog} />
      <EditEmailRouteDialog
        route={editRoute}
        onOpenChange={(open) => {
          if (!open) setEditRoute(null)
        }}
      />
      <DeleteEmailRouteDialog
        route={deleteRoute}
        onOpenChange={(open) => {
          if (!open) setDeleteRoute(null)
        }}
      />

      {/* Bulk action bar */}
      <BulkActionBar selectedCount={selectedIds.size} selectedIds={Array.from(selectedIds)} onClearSelection={() => setSelectedIds(new Set())} actions={bulkActions} />
    </PageContainer>
  )
}
