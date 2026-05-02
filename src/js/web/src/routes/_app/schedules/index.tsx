import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useState } from "react"
import {
  AlertCircle,
  Calendar,
  CheckCircle2,
  Clock,
  Download,
  Eye,
  Globe,
  Home,
  Loader2,
  MoreVertical,
  Pencil,
  Plus,
  Search,
  SlidersHorizontal,
  Star,
  Trash2,
  X,
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  useSchedules,
  useCreateSchedule,
  useDeleteSchedule,
  useCheckSchedule,
  type Schedule,
  type ScheduleCreate,
} from "@/lib/api/hooks/schedules"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime } from "@/lib/date-utils"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"

export const Route = createFileRoute("/_app/schedules/")({
  component: SchedulesPage,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZE = 25

const scheduleTypeLabels: Record<string, string> = {
  business_hours: "Business Hours",
  holiday: "Holiday",
  custom: "Custom",
}

const scheduleTypeVariant: Record<string, "default" | "secondary" | "outline"> = {
  business_hours: "default",
  holiday: "secondary",
  custom: "outline",
}

const scheduleTypeIcons: Record<string, typeof Clock> = {
  business_hours: Clock,
  holiday: Calendar,
  custom: SlidersHorizontal,
}

const COMMON_TIMEZONES = [
  "America/New_York",
  "America/Chicago",
  "America/Denver",
  "America/Los_Angeles",
  "America/Phoenix",
  "America/Anchorage",
  "Pacific/Honolulu",
  "America/Toronto",
  "America/Vancouver",
  "Europe/London",
  "Europe/Paris",
  "Europe/Berlin",
  "Asia/Tokyo",
  "Asia/Shanghai",
  "Asia/Kolkata",
  "Australia/Sydney",
  "Pacific/Auckland",
  "UTC",
]

const csvHeaders: CsvHeader<Schedule>[] = [
  { label: "Name", accessor: (s) => s.name },
  { label: "Type", accessor: (s) => scheduleTypeLabels[s.scheduleType] ?? s.scheduleType },
  { label: "Timezone", accessor: (s) => s.timezone },
  { label: "Default", accessor: (s) => (s.isDefault ? "Yes" : "No") },
  { label: "Created", accessor: (s) => (s.createdAt ? formatDateTime(s.createdAt) : "") },
  { label: "Updated", accessor: (s) => (s.updatedAt ? formatDateTime(s.updatedAt) : "") },
]

// -- Status badge (per-row) ---------------------------------------------------

function ScheduleStatusBadge({ scheduleId }: { scheduleId: string }) {
  const { data, isLoading } = useCheckSchedule(scheduleId)

  if (isLoading) {
    return (
      <Badge variant="outline" className="gap-1 text-muted-foreground">
        <Loader2 className="h-3 w-3 animate-spin" />
        Checking
      </Badge>
    )
  }

  if (!data) {
    return (
      <Badge variant="outline" className="gap-1 text-muted-foreground">
        --
      </Badge>
    )
  }

  if (data.isOpen) {
    return (
      <Badge className="gap-1 bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">
        <CheckCircle2 className="h-3 w-3" />
        Open
      </Badge>
    )
  }

  return (
    <Badge variant="outline" className="gap-1">
      <XCircle className="h-3 w-3" />
      Closed
    </Badge>
  )
}

// -- New Schedule Dialog ------------------------------------------------------

function NewScheduleDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const navigate = useNavigate()
  const createSchedule = useCreateSchedule()

  const [name, setName] = useState("")
  const [scheduleType, setScheduleType] = useState<ScheduleCreate["scheduleType"]>("business_hours")
  const [timezone, setTimezone] = useState("America/New_York")

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return

    createSchedule.mutate(
      { name: name.trim(), scheduleType, timezone },
      {
        onSuccess: (data) => {
          onOpenChange(false)
          setName("")
          setScheduleType("business_hours")
          setTimezone("America/New_York")
          navigate({ to: "/schedules/$scheduleId", params: { scheduleId: data.id } })
        },
      },
    )
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New Schedule</DialogTitle>
          <DialogDescription>Create a new schedule to define operating hours or holidays.</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="schedule-name">Name</Label>
            <Input
              id="schedule-name"
              placeholder="e.g., Main Office Hours"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="schedule-type">Type</Label>
            <Select value={scheduleType} onValueChange={(v) => setScheduleType(v as ScheduleCreate["scheduleType"])}>
              <SelectTrigger id="schedule-type">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="business_hours">Business Hours</SelectItem>
                <SelectItem value="holiday">Holiday</SelectItem>
                <SelectItem value="custom">Custom</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="schedule-timezone">Timezone</Label>
            <Select value={timezone} onValueChange={setTimezone}>
              <SelectTrigger id="schedule-timezone">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {COMMON_TIMEZONES.map((tz) => (
                  <SelectItem key={tz} value={tz}>
                    {tz.replace(/_/g, " ")}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!name.trim() || createSchedule.isPending}>
              {createSchedule.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Create Schedule
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// -- Main page ----------------------------------------------------------------

function SchedulesPage() {
  useDocumentTitle("Schedules")

  const navigate = useNavigate()
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [page, setPage] = useState(1)
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)
  const [dialogOpen, setDialogOpen] = useState(false)

  // Reset page when debounced search changes
  useEffect(() => {
    setPage(1)
  }, [debouncedSearch])

  const { data, isLoading, isError, refetch } = useSchedules({
    page,
    pageSize: PAGE_SIZE,
    search: debouncedSearch || undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
  })

  const deleteSchedule = useDeleteSchedule()

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  const schedules = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  // filteredItems (no client-side filters currently, but keeps export consistent)
  const filteredItems = useMemo(() => schedules, [schedules])

  // Selection helpers
  const allVisibleIds = useMemo(() => filteredItems.map((s) => s.id), [filteredItems])
  const allSelected = filteredItems.length > 0 && filteredItems.every((s) => selectedIds.has(s.id))
  const someSelected = filteredItems.some((s) => selectedIds.has(s.id))

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

  const handleSort = useCallback(
    (key: string) => {
      const next = nextSortDirection(sortKey, sortDir, key)
      setSortKey(next.sort)
      setSortDir(next.direction)
    },
    [sortKey, sortDir],
  )

  const handleRowClick = useCallback(
    (scheduleId: string) => {
      navigate({ to: "/schedules/$scheduleId", params: { scheduleId } })
    },
    [navigate],
  )

  // Bulk actions
  const bulkActions = useMemo(
    () => [
      createBulkDeleteAction(
        (id) => deleteSchedule.mutateAsync(id),
        () => refetch(),
        { label: "Delete Selected" },
      ),
      createExportAction<Schedule>(
        "schedules-selected",
        csvHeaders,
        (ids) => filteredItems.filter((s) => ids.includes(s.id)),
      ),
    ],
    [deleteSchedule, refetch, filteredItems],
  )

  // Export all visible
  const handleExportAll = useCallback(() => {
    if (!filteredItems.length) return
    exportToCsv("schedules", csvHeaders, filteredItems)
  }, [filteredItems])

  const hasData = filteredItems.length > 0
  const hasActiveFilters = search !== ""

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
          <BreadcrumbPage>Schedules</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Workspace"
        title="Schedules"
        description="Manage business hours, holiday schedules, and custom time windows."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!hasData}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
            <Button size="sm" onClick={() => setDialogOpen(true)}>
              <Plus className="mr-2 h-4 w-4" /> New schedule
            </Button>
          </div>
        }
      />

      {/* Search */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search schedules..."
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

      {/* Content */}
      <PageSection delay={0.1}>
        {isLoading ? (
          <SkeletonTable rows={6} />
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load schedules"
            description="Something went wrong while fetching your schedules. Please try again."
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Try again
              </Button>
            }
          />
        ) : schedules.length === 0 && !hasActiveFilters ? (
          <EmptyState
            icon={Calendar}
            title="No schedules yet"
            description="Create your first schedule to define business hours, holidays, or custom operating windows."
            action={
              <Button size="sm" onClick={() => setDialogOpen(true)}>
                <Plus className="mr-2 h-4 w-4" /> New schedule
              </Button>
            }
          />
        ) : schedules.length === 0 ? (
          <EmptyState
            icon={Calendar}
            variant="no-results"
            title="No results found"
            description="No schedules match your current search. Try adjusting your search terms."
            action={
              <Button variant="outline" size="sm" onClick={() => setSearch("")}>
                Clear search
              </Button>
            }
          />
        ) : (
          <div className="space-y-3">
            {/* Result count & pagination info */}
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">
                {total} schedule{total === 1 ? "" : "s"}
                {hasActiveFilters && " (filtered)"}
              </p>
              {totalPages > 1 && (
                <p className="text-xs text-muted-foreground">
                  Page {page} of {totalPages}
                </p>
              )}
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
              <Table aria-label="Schedules">
                <TableHeader className="sticky top-0 z-10 bg-background">
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all schedules"
                      />
                    </TableHead>
                    <SortableHeader
                      label="Name"
                      sortKey="name"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <TableHead className="hidden md:table-cell">Type</TableHead>
                    <SortableHeader
                      label="Timezone"
                      sortKey="timezone"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden md:table-cell"
                    />
                    <TableHead className="hidden lg:table-cell">Entries</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="w-16 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredItems.map((schedule, index) => (
                    <ScheduleRow
                      key={schedule.id}
                      schedule={schedule}
                      index={index}
                      selected={selectedIds.has(schedule.id)}
                      onToggle={() => toggleOne(schedule.id)}
                      onRowClick={() => handleRowClick(schedule.id)}
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

      {/* New schedule dialog */}
      <NewScheduleDialog open={dialogOpen} onOpenChange={setDialogOpen} />

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

function ScheduleRow({
  schedule,
  index,
  selected,
  onToggle,
  onRowClick,
}: {
  schedule: Schedule
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
}) {
  const deleteSchedule = useDeleteSchedule()
  const [itemToDelete, setItemToDelete] = useState<{ id: string; name: string } | null>(null)

  const handleConfirmDelete = () => {
    if (itemToDelete) {
      deleteSchedule.mutate(itemToDelete.id, {
        onSuccess: () => {
          setTimeout(() => {
            const searchInput = document.querySelector<HTMLInputElement>('input[placeholder*="Search"]')
            if (searchInput) {
              searchInput.focus()
            }
          }, 0)
        },
      })
      setItemToDelete(null)
    }
  }

  return (
    <TableRow
      data-state={selected ? "selected" : undefined}
      className={`cursor-pointer hover:bg-muted/50 transition-colors ${index % 2 === 1 ? "bg-muted/20" : ""}`}
      onClick={(e) => {
        const target = e.target as HTMLElement
        if (target.closest("[role=checkbox]") || target.closest("a") || target.closest("button") || target.closest("[data-slot=dropdown]")) return
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
          aria-label={`Select ${schedule.name}`}
        />
      </TableCell>
      <TableCell>
        <Link
          to="/schedules/$scheduleId"
          params={{ scheduleId: schedule.id }}
          className="group flex items-center gap-2"
          onClick={(e) => e.stopPropagation()}
        >
          {(() => {
            const TypeIcon = scheduleTypeIcons[schedule.scheduleType] ?? Clock
            return <TypeIcon className="h-4 w-4 shrink-0 text-muted-foreground" />
          })()}
          <span className="font-medium group-hover:underline">{schedule.name}</span>
          {schedule.isDefault && (
            <Badge className="ml-1 gap-1 bg-amber-100 text-amber-700 hover:bg-amber-100 dark:bg-amber-900/30 dark:text-amber-400" variant="secondary">
              <Star className="h-3 w-3 fill-current" />
              Default
            </Badge>
          )}
        </Link>
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <Badge variant={scheduleTypeVariant[schedule.scheduleType] ?? "outline"} className="gap-1">
          {(() => {
            const TypeIcon = scheduleTypeIcons[schedule.scheduleType] ?? Clock
            return <TypeIcon className="h-3 w-3" />
          })()}
          {scheduleTypeLabels[schedule.scheduleType] ?? schedule.scheduleType}
        </Badge>
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <Badge variant="outline" className="gap-1 font-normal text-muted-foreground">
          <Globe className="h-3 w-3" />
          {schedule.timezone.replace(/_/g, " ")}
        </Badge>
      </TableCell>
      <TableCell className="hidden lg:table-cell">
        {schedule.entries && schedule.entries.length > 0 ? (
          <span className="text-sm text-muted-foreground">
            {schedule.entries.length} {schedule.entries.length === 1 ? "entry" : "entries"}
          </span>
        ) : (
          <span className="text-sm text-muted-foreground">--</span>
        )}
      </TableCell>
      <TableCell>
        <ScheduleStatusBadge scheduleId={schedule.id} />
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
              <span className="sr-only">Actions</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link to="/schedules/$scheduleId" params={{ scheduleId: schedule.id }}>
                <Eye className="mr-2 h-4 w-4" />
                View details
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link to="/schedules/$scheduleId" params={{ scheduleId: schedule.id }} search={{ edit: true }}>
                <Pencil className="mr-2 h-4 w-4" />
                Edit
              </Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="text-destructive focus:text-destructive"
              onClick={() => setItemToDelete({ id: schedule.id, name: schedule.name })}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>

      <AlertDialog open={!!itemToDelete} onOpenChange={(open) => !open && setItemToDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete schedule?</AlertDialogTitle>
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
    </TableRow>
  )
}
