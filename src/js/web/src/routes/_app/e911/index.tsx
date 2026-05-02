import { toast } from "sonner"
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Download,
  Eye,
  Home,
  Loader2,
  MoreVertical,
  Pencil,
  Plus,
  Search,
  ShieldAlert,
  Trash2,
  X,
  XCircle,
} from "lucide-react"
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
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  useE911Registrations,
  useDeleteE911Registration,
  useValidateE911Registration,
  useUnregisteredPhoneNumbers,
  type E911Registration,
  type UnregisteredPhoneNumber,
} from "@/lib/api/hooks/e911"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { useAuthStore } from "@/lib/auth"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"

export const Route = createFileRoute("/_app/e911/")({
  component: E911Page,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_STORAGE_KEY = "e911-page-size"

function getStoredPageSize(): number {
  try {
    const stored = localStorage.getItem(PAGE_SIZE_STORAGE_KEY)
    if (stored) {
      const parsed = Number(stored)
      if ((PAGE_SIZES as readonly number[]).includes(parsed)) return parsed
    }
  } catch {
    /* localStorage unavailable */
  }
  return DEFAULT_PAGE_SIZE
}

const csvHeaders: CsvHeader<E911Registration>[] = [
  { label: "Phone Number", accessor: (r) => r.phoneNumberDisplay ?? "" },
  { label: "Phone Number Label", accessor: (r) => r.phoneNumberLabel ?? "" },
  { label: "Address Line 1", accessor: (r) => r.addressLine1 },
  { label: "Address Line 2", accessor: (r) => r.addressLine2 ?? "" },
  { label: "City", accessor: (r) => r.city },
  { label: "State", accessor: (r) => r.state },
  { label: "Postal Code", accessor: (r) => r.postalCode },
  { label: "Country", accessor: (r) => r.country },
  { label: "Validated", accessor: (r) => (r.validated ? "Yes" : "No") },
  { label: "Validated At", accessor: (r) => r.validatedAt ?? "" },
  { label: "Carrier Reg ID", accessor: (r) => r.carrierRegistrationId ?? "" },
  { label: "Location", accessor: (r) => r.locationName ?? "" },
]

// -- E911 Row -----------------------------------------------------------------

function E911Row({
  reg,
  index,
  selected,
  onToggle,
  onRowClick,
}: {
  reg: E911Registration
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
}) {
  const validateMutation = useValidateE911Registration(reg.id)
  const deleteMutation = useDeleteE911Registration()

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
          aria-label={`Select ${reg.phoneNumberDisplay ?? reg.id}`}
        />
      </TableCell>
      <TableCell>
        <Link
          to="/e911/$registrationId"
          params={{ registrationId: reg.id }}
          className="group flex flex-col gap-0.5"
          onClick={(e) => e.stopPropagation()}
        >
          <span className="font-medium group-hover:underline font-mono text-sm">
            {reg.phoneNumberDisplay ?? "No number"}
          </span>
          {reg.phoneNumberLabel && (
            <span className="text-xs text-muted-foreground">{reg.phoneNumberLabel}</span>
          )}
        </Link>
      </TableCell>
      <TableCell>
        <Link
          to="/e911/$registrationId"
          params={{ registrationId: reg.id }}
          className="group-hover:underline text-sm"
          onClick={(e) => e.stopPropagation()}
        >
          {reg.addressLine1}
          {reg.addressLine2 ? `, ${reg.addressLine2}` : ""}
        </Link>
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <span className="text-sm">{reg.city}, {reg.state} {reg.postalCode}</span>
      </TableCell>
      <TableCell>
        {reg.validated ? (
          <Badge className="bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/30">
            <CheckCircle2 className="mr-1 h-3 w-3" />
            Validated
          </Badge>
        ) : (
          <Badge variant="outline" className="border-red-500/30 text-red-600 dark:text-red-400">
            <XCircle className="mr-1 h-3 w-3" />
            Pending
          </Badge>
        )}
      </TableCell>
      <TableCell className="hidden md:table-cell">
        {reg.carrierRegistrationId ? (
          <span className="font-mono text-xs text-muted-foreground">{reg.carrierRegistrationId}</span>
        ) : (
          <span className="text-xs text-muted-foreground">--</span>
        )}
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
              <span className="sr-only">Actions for {reg.phoneNumberDisplay ?? reg.id}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link to="/e911/$registrationId" params={{ registrationId: reg.id }}>
                <Eye className="mr-2 h-4 w-4" />
                View details
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link to="/e911/$registrationId" params={{ registrationId: reg.id }} search={{ edit: true }}>
                <Pencil className="mr-2 h-4 w-4" />
                Edit
              </Link>
            </DropdownMenuItem>
            {!reg.validated && (
              <DropdownMenuItem
                disabled={validateMutation.isPending}
                onClick={() => validateMutation.mutate(undefined, {
                  onSuccess: () => toast.success("E911 registration validated"),
                  onError: (err) => toast.error("Failed to validate E911 registration", {
                    description: err instanceof Error ? err.message : undefined,
                  }),
                })}
              >
                {validateMutation.isPending ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <CheckCircle2 className="mr-2 h-4 w-4" />
                )}
                Validate
              </DropdownMenuItem>
            )}
            <DropdownMenuSeparator />
            <DropdownMenuItem
              variant="destructive"
              disabled={deleteMutation.isPending}
              onClick={() => deleteMutation.mutate(reg.id, {
                onSuccess: () => toast.success("E911 registration deleted"),
                onError: (err) => toast.error("Failed to delete E911 registration", {
                  description: err instanceof Error ? err.message : undefined,
                }),
              })}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  )
}

// -- Register dialog ----------------------------------------------------------

// -- Main page ----------------------------------------------------------------

function E911Page() {
  useDocumentTitle("E911 Addresses")

  const { currentTeam } = useAuthStore()
  const navigate = useNavigate()
  const teamId = currentTeam?.id ?? ""

  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(getStoredPageSize)

  const handlePageSizeChange = useCallback((value: string) => {
    const size = Number(value)
    setPageSize(size)
    setPage(1)
    try {
      localStorage.setItem(PAGE_SIZE_STORAGE_KEY, String(size))
    } catch {
      /* localStorage unavailable */
    }
  }, [])

  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  const handleSort = useCallback((key: string) => {
    const next = nextSortDirection(sortKey, sortDir, key)
    setSortKey(next.sort)
    setSortDir(next.direction)
  }, [sortKey, sortDir])

  const searchInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    setPage(1)
  }, [debouncedSearch])

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey) {
        const target = e.target as HTMLElement
        if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return
        e.preventDefault()
        searchInputRef.current?.focus()
      }
    }
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [])

  const { data, isLoading, isError, refetch } = useE911Registrations({
    page,
    pageSize,
    search: debouncedSearch || undefined,
    teamId: teamId || undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
  })

  const deleteMutation = useDeleteE911Registration()
  const { data: unregistered } = useUnregisteredPhoneNumbers(teamId)

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  const items = data?.items ?? []

  // Selection helpers
  const allVisibleIds = useMemo(() => items.map((r) => r.id), [items])
  const allSelected = items.length > 0 && items.every((r) => selectedIds.has(r.id))
  const someSelected = items.some((r) => selectedIds.has(r.id))

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

  // Bulk actions
  const bulkActions = useMemo(
    () => [
      createBulkDeleteAction(
        async (id) => {
          await deleteMutation.mutateAsync(id)
        },
        () => {
          setSelectedIds(new Set())
          deleteMutation.reset()
        },
      ),
      createExportAction<E911Registration>(
        "e911-registrations-selected",
        csvHeaders,
        (ids) => items.filter((r) => ids.includes(r.id)),
      ),
    ],
    [items, deleteMutation],
  )

  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / pageSize))
  const hasData = items.length > 0
  const unregisteredCount = unregistered?.length ?? 0

  const handleRowClick = useCallback(
    (registrationId: string) => {
      navigate({ to: "/e911/$registrationId", params: { registrationId } })
    },
    [navigate],
  )

  const handleExportAll = useCallback(() => {
    if (!items.length) return
    exportToCsv("e911-registrations", csvHeaders, items)
  }, [items])

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
          <BreadcrumbPage>E911 Addresses</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Compliance"
        title={
          <span className="flex items-center gap-3">
            E911 Addresses
            {unregisteredCount > 0 && (
              <Badge variant="outline" className="border-amber-500/40 text-amber-600 dark:text-amber-400 text-xs font-normal">
                <AlertTriangle className="mr-1 h-3 w-3" />
                {unregisteredCount} unregistered
              </Badge>
            )}
          </span>
        }
        description="Manage E911 emergency address registrations for your phone numbers."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!hasData}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
            {teamId && (
              <Button size="sm" asChild>
                <Link to="/e911/new">
                  <Plus className="mr-2 h-4 w-4" /> Register Address
                </Link>
              </Button>
            )}
          </div>
        }
      />

      {/* Search */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              ref={searchInputRef}
              placeholder="Search by address..."
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
        </div>
      </PageSection>

      {/* Unregistered numbers warning */}
      {unregisteredCount > 0 && (
        <PageSection delay={0.05}>
          <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-500" />
              <div className="flex-1">
                <p className="font-medium text-sm">
                  {unregisteredCount} phone number{unregisteredCount === 1 ? "" : "s"} without E911 registration
                </p>
                <p className="mt-1 text-sm text-muted-foreground">
                  The following numbers do not have E911 addresses registered. Emergency services may not be able to locate callers using these numbers.
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {(unregistered ?? []).map((pn: UnregisteredPhoneNumber) => (
                    <Badge key={pn.id} variant="outline" className="border-amber-500/40 text-amber-600 dark:text-amber-400">
                      <AlertTriangle className="mr-1 h-3 w-3" />
                      {pn.number}{pn.label ? ` (${pn.label})` : ""}
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </PageSection>
      )}

      {/* Registrations table */}
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
            title="Unable to load E911 registrations"
            description="Something went wrong while fetching your E911 registrations. Please try again."
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Try again
              </Button>
            }
          />
        ) : !hasData && !search ? (
          <EmptyState
            icon={ShieldAlert}
            title="No E911 registrations"
            description="Register E911 addresses for your phone numbers to ensure emergency services can locate callers."
            action={
              teamId ? (
                <Button size="sm" asChild>
                  <Link to="/e911/new">
                    <Plus className="mr-2 h-4 w-4" /> Register Address
                  </Link>
                </Button>
              ) : undefined
            }
          />
        ) : !hasData ? (
          <EmptyState
            icon={ShieldAlert}
            variant="no-results"
            title="No results found"
            description="No E911 registrations match your search. Try adjusting your query."
            action={
              <Button variant="outline" size="sm" onClick={() => setSearch("")}>
                Clear search
              </Button>
            }
          />
        ) : (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">
                {data?.total ?? items.length} registration{(data?.total ?? items.length) === 1 ? "" : "s"}
              </p>
              {totalPages > 1 && (
                <p className="text-xs text-muted-foreground">
                  Page {page} of {totalPages}
                </p>
              )}
            </div>

            <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
              <Table aria-label="E911 Registrations">
                <TableHeader className="sticky top-0 z-10 bg-background">
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all registrations"
                      />
                    </TableHead>
                    <SortableHeader
                      label="Phone Number"
                      sortKey="phone_number_display"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Address"
                      sortKey="address_line1"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="City / State"
                      sortKey="city"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden md:table-cell"
                    />
                    <SortableHeader
                      label="Validated"
                      sortKey="validated"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <TableHead className="hidden md:table-cell">Carrier Reg ID</TableHead>
                    <TableHead className="w-16 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((reg: E911Registration, index: number) => (
                    <E911Row
                      key={reg.id}
                      reg={reg}
                      index={index}
                      selected={selectedIds.has(reg.id)}
                      onToggle={() => toggleOne(reg.id)}
                      onRowClick={() => handleRowClick(reg.id)}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>

            {/* Pagination */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">Rows per page</span>
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
    </PageContainer>
  )
}
