import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useEffect, useState } from "react"
import {
  AlertCircle,
  Calendar,
  CheckCircle2,
  Clock,
  Home,
  Loader2,
  Plus,
  Search,
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
import { Button } from "@/components/ui/button"
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
  useCheckSchedule,
  type Schedule,
  type ScheduleCreate,
} from "@/lib/api/hooks/schedules"
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

  const schedules = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

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
          <Button size="sm" onClick={() => setDialogOpen(true)}>
            <Plus className="mr-2 h-4 w-4" /> New schedule
          </Button>
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
                <TableHeader>
                  <TableRow>
                    <SortableHeader
                      label="Name"
                      sortKey="name"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <TableHead>Type</TableHead>
                    <SortableHeader
                      label="Timezone"
                      sortKey="timezone"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <TableHead>Default</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {schedules.map((schedule) => (
                    <ScheduleRow
                      key={schedule.id}
                      schedule={schedule}
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
    </PageContainer>
  )
}

// -- Table row ----------------------------------------------------------------

function ScheduleRow({
  schedule,
  onRowClick,
}: {
  schedule: Schedule
  onRowClick: () => void
}) {
  return (
    <TableRow
      className="cursor-pointer hover:bg-muted/50 transition-colors"
      onClick={(e) => {
        const target = e.target as HTMLElement
        if (target.closest("a") || target.closest("button")) return
        onRowClick()
      }}
    >
      <TableCell>
        <Link
          to="/schedules/$scheduleId"
          params={{ scheduleId: schedule.id }}
          className="group flex items-center gap-2"
          onClick={(e) => e.stopPropagation()}
        >
          <Clock className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium group-hover:underline">{schedule.name}</span>
        </Link>
      </TableCell>
      <TableCell>
        <Badge variant={scheduleTypeVariant[schedule.scheduleType] ?? "outline"}>
          {scheduleTypeLabels[schedule.scheduleType] ?? schedule.scheduleType}
        </Badge>
      </TableCell>
      <TableCell>
        <span className="text-sm text-muted-foreground">{schedule.timezone.replace(/_/g, " ")}</span>
      </TableCell>
      <TableCell>
        {schedule.isDefault ? (
          <Badge className="gap-1 bg-blue-100 text-blue-700 hover:bg-blue-100 dark:bg-blue-900/30 dark:text-blue-400">
            Default
          </Badge>
        ) : (
          <span className="text-sm text-muted-foreground">--</span>
        )}
      </TableCell>
      <TableCell>
        <ScheduleStatusBadge scheduleId={schedule.id} />
      </TableCell>
    </TableRow>
  )
}
