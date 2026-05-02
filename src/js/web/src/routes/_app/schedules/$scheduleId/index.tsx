import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useEffect, useMemo, useState } from "react"
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Calendar,
  CheckCircle2,
  Clock,
  Copy,
  Grid3x3,
  Link2,
  List,
  Loader2,
  MoreHorizontal,
  Pencil,
  Plus,
  Trash2,
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Badge } from "@/components/ui/badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { CopyButton } from "@/components/ui/copy-button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { formatDateTime, formatRelativeTime } from "@/lib/date-utils"
import {
  useSchedule,
  useUpdateSchedule,
  useDeleteSchedule,
  useCheckSchedule,
  useCreateScheduleEntry,
  useDeleteScheduleEntry,
  type Schedule,
  type ScheduleEntry,
  type ScheduleEntryCreate,
} from "@/lib/api/hooks/schedules"
import { toast } from "sonner"
import { useTimeConditions } from "@/lib/api/hooks/call-routing"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { useDocumentTitle } from "@/hooks/use-document-title"

export const Route = createFileRoute("/_app/schedules/$scheduleId/")({
  component: ScheduleDetailPage,
  validateSearch: (search: Record<string, unknown>): { tab?: string; edit?: boolean } => ({
    tab: (search.tab as string) || undefined,
    edit: search.edit === true || search.edit === "true" || undefined,
  }),
})

// -- Constants ----------------------------------------------------------------

const DAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

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

const scheduleTypeLabels: Record<string, string> = {
  business_hours: "Business Hours",
  holiday: "Holiday",
  custom: "Custom",
}

// -- Status badge -------------------------------------------------------------

function CurrentStatusBadge({ scheduleId }: { scheduleId: string }) {
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
        Unknown
      </Badge>
    )
  }

  if (data.isOpen) {
    return (
      <Badge className="gap-1 bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">
        <CheckCircle2 className="h-3 w-3" />
        Currently Open
      </Badge>
    )
  }

  return (
    <Badge variant="outline" className="gap-1">
      <XCircle className="h-3 w-3" />
      Currently Closed
    </Badge>
  )
}

// -- Add Entry Row (inline form) ----------------------------------------------

function AddWeeklyEntryRow({
  scheduleId,
  dayOfWeek,
}: {
  scheduleId: string
  dayOfWeek: number
}) {
  const createEntry = useCreateScheduleEntry(scheduleId)
  const [adding, setAdding] = useState(false)
  const [startTime, setStartTime] = useState("09:00")
  const [endTime, setEndTime] = useState("17:00")

  const handleSave = () => {
    createEntry.mutate(
      { dayOfWeek, startTime, endTime, isClosed: false },
      {
        onSuccess: () => {
          setAdding(false)
          setStartTime("09:00")
          setEndTime("17:00")
        },
      },
    )
  }

  const handleMarkClosed = () => {
    createEntry.mutate(
      { dayOfWeek, startTime: "00:00", endTime: "00:00", isClosed: true },
      {
        onSuccess: () => setAdding(false),
      },
    )
  }

  if (!adding) {
    return (
      <Button variant="ghost" size="sm" className="h-7 gap-1 text-xs" onClick={() => setAdding(true)}>
        <Plus className="h-3 w-3" />
        Add hours
      </Button>
    )
  }

  return (
    <div className="flex items-center gap-2">
      <Input
        type="time"
        value={startTime}
        onChange={(e) => setStartTime(e.target.value)}
        className="h-7 w-28 text-xs"
      />
      <span className="text-xs text-muted-foreground">to</span>
      <Input
        type="time"
        value={endTime}
        onChange={(e) => setEndTime(e.target.value)}
        className="h-7 w-28 text-xs"
      />
      <Button size="sm" className="h-7 text-xs" onClick={handleSave} disabled={createEntry.isPending}>
        {createEntry.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : "Save"}
      </Button>
      <Button
        variant="outline"
        size="sm"
        className="h-7 text-xs"
        onClick={handleMarkClosed}
        disabled={createEntry.isPending}
      >
        Closed
      </Button>
      <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => setAdding(false)}>
        Cancel
      </Button>
    </div>
  )
}

// -- Existing entry display ---------------------------------------------------

function EntryDisplay({
  entry,
  scheduleId,
}: {
  entry: ScheduleEntry
  scheduleId: string
}) {
  const deleteEntry = useDeleteScheduleEntry(scheduleId)
  const [confirmDelete, setConfirmDelete] = useState(false)

  const handleDelete = () => {
    deleteEntry.mutate(entry.id, {
      onSuccess: () => setConfirmDelete(false),
    })
  }

  const deleteButton = (
    <Button
      variant="ghost"
      size="sm"
      className="h-6 w-6 p-0 text-muted-foreground hover:text-destructive"
      onClick={() => setConfirmDelete(true)}
      disabled={deleteEntry.isPending}
    >
      {deleteEntry.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />}
    </Button>
  )

  const deleteDialog = (
    <AlertDialog open={confirmDelete} onOpenChange={(open) => !open && setConfirmDelete(false)}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            Delete schedule entry?
          </AlertDialogTitle>
          <AlertDialogDescription>
            This will permanently remove this schedule entry. This action cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={deleteEntry.isPending}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            className={buttonVariants({ variant: "destructive" })}
            onClick={handleDelete}
            disabled={deleteEntry.isPending}
          >
            {deleteEntry.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {deleteEntry.isPending ? "Deleting..." : "Delete"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )

  if (entry.isClosed) {
    return (
      <div className="flex items-center gap-2">
        <Badge variant="outline" className="text-xs text-muted-foreground">
          Closed
        </Badge>
        {deleteButton}
        {deleteDialog}
      </div>
    )
  }

  return (
    <div className="flex items-center gap-2">
      <span className="text-sm">
        {entry.startTime} - {entry.endTime}
      </span>
      {deleteButton}
      {deleteDialog}
    </div>
  )
}

// -- Add Holiday Entry --------------------------------------------------------

function AddHolidayEntry({ scheduleId }: { scheduleId: string }) {
  const createEntry = useCreateScheduleEntry(scheduleId)
  const [adding, setAdding] = useState(false)
  const [date, setDate] = useState("")
  const [label, setLabel] = useState("")
  const [isClosed, setIsClosed] = useState(true)
  const [startTime, setStartTime] = useState("09:00")
  const [endTime, setEndTime] = useState("17:00")

  const handleSave = () => {
    if (!date) return
    const payload: ScheduleEntryCreate = {
      dayOfWeek: null,
      date,
      label: label || null,
      isClosed,
      startTime: isClosed ? "00:00" : startTime,
      endTime: isClosed ? "00:00" : endTime,
    }
    createEntry.mutate(payload, {
      onSuccess: () => {
        setAdding(false)
        setDate("")
        setLabel("")
        setIsClosed(true)
        setStartTime("09:00")
        setEndTime("17:00")
      },
    })
  }

  if (!adding) {
    return (
      <Button variant="outline" size="sm" onClick={() => setAdding(true)}>
        <Plus className="mr-2 h-4 w-4" />
        Add holiday
      </Button>
    )
  }

  return (
    <div className="space-y-3 rounded-lg border border-border/60 bg-muted/20 p-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-2">
          <Label>Date</Label>
          <Input type="date" value={date} onChange={(e) => setDate(e.target.value)} required />
        </div>
        <div className="space-y-2">
          <Label>Label</Label>
          <Input placeholder="e.g., Christmas Day" value={label} onChange={(e) => setLabel(e.target.value)} />
        </div>
      </div>
      <div className="flex items-center gap-3">
        <Switch checked={isClosed} onCheckedChange={setIsClosed} id="holiday-closed" />
        <Label htmlFor="holiday-closed">Closed all day</Label>
      </div>
      {!isClosed && (
        <div className="flex items-center gap-2">
          <Input type="time" value={startTime} onChange={(e) => setStartTime(e.target.value)} className="w-32" />
          <span className="text-sm text-muted-foreground">to</span>
          <Input type="time" value={endTime} onChange={(e) => setEndTime(e.target.value)} className="w-32" />
        </div>
      )}
      <div className="flex items-center gap-2">
        <Button size="sm" onClick={handleSave} disabled={!date || createEntry.isPending}>
          {createEntry.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          Add
        </Button>
        <Button variant="ghost" size="sm" onClick={() => setAdding(false)}>
          Cancel
        </Button>
      </div>
    </div>
  )
}

// -- Delete Schedule Dialog ---------------------------------------------------

function DeleteScheduleDialog({
  scheduleName,
  onDelete,
  isPending,
  open: controlledOpen,
  onOpenChange,
}: {
  scheduleName: string
  onDelete: () => void
  isPending: boolean
  open?: boolean
  onOpenChange?: (open: boolean) => void
}) {
  const [internalOpen, setInternalOpen] = useState(false)
  const isControlled = controlledOpen !== undefined
  const open = isControlled ? controlledOpen : internalOpen
  const setOpen = isControlled ? (onOpenChange ?? (() => {})) : setInternalOpen

  return (
    <>
      {!isControlled && (
        <Button variant="destructive" size="sm" onClick={() => setOpen(true)}>
          <Trash2 className="mr-2 h-4 w-4" />
          Delete
        </Button>
      )}
      <AlertDialog open={open} onOpenChange={setOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete "{scheduleName}"?
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete this schedule and all its entries. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setOpen(false)} disabled={isPending}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              className={buttonVariants({ variant: "destructive" })}
              onClick={onDelete}
              disabled={isPending}
            >
              {isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {isPending ? "Deleting..." : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// -- Weekly View Grid ---------------------------------------------------------

const GRID_START_HOUR = 6
const GRID_END_HOUR = 22
const GRID_TOTAL_HOURS = GRID_END_HOUR - GRID_START_HOUR // 16

const DAY_ABBREVIATIONS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

/** Parse "HH:MM" into fractional hours (e.g. "09:30" => 9.5). */
function parseTime(time: string): number {
  const [h, m] = time.split(":").map(Number)
  return h + m / 60
}

/** Format fractional hour to a readable label, e.g. 9 => "9 AM", 13.5 => "1:30 PM". */
function formatHourLabel(hour: number): string {
  const h = Math.floor(hour)
  const m = Math.round((hour - h) * 60)
  const suffix = h >= 12 ? "PM" : "AM"
  const display = h === 0 ? 12 : h > 12 ? h - 12 : h
  return m > 0 ? `${display}:${String(m).padStart(2, "0")} ${suffix}` : `${display} ${suffix}`
}

function WeeklyViewGrid({
  weeklyEntries,
}: {
  weeklyEntries: Map<number, ScheduleEntry[]>
}) {
  const hasAnyEntries = Array.from(weeklyEntries.values()).some((entries) => entries.length > 0)

  if (!hasAnyEntries) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <Calendar className="mb-3 h-10 w-10 text-muted-foreground/40" />
        <p className="text-sm font-medium text-muted-foreground">No schedule entries</p>
        <p className="text-xs text-muted-foreground/70">
          Add hours using the list view to see them displayed here.
        </p>
      </div>
    )
  }

  const hourLabels: number[] = []
  for (let h = GRID_START_HOUR; h <= GRID_END_HOUR; h++) {
    hourLabels.push(h)
  }

  return (
    <TooltipProvider delayDuration={200}>
      <div className="overflow-x-auto">
        <div className="min-w-[600px]">
          {/* Header row: day names */}
          <div className="grid grid-cols-[60px_repeat(7,1fr)] border-b border-border/60">
            <div /> {/* empty corner cell */}
            {DAY_ABBREVIATIONS.map((day) => (
              <div
                key={day}
                className="px-1 py-2 text-center text-xs font-semibold text-muted-foreground"
              >
                {day}
              </div>
            ))}
          </div>

          {/* Grid body */}
          <div className="grid grid-cols-[60px_repeat(7,1fr)]">
            {/* Hour labels column */}
            <div className="relative">
              {hourLabels.map((hour) => (
                <div
                  key={hour}
                  className="flex h-7 items-start justify-end pr-2 text-[10px] text-muted-foreground/70"
                  style={{ marginTop: hour === GRID_START_HOUR ? 0 : undefined }}
                >
                  {formatHourLabel(hour)}
                </div>
              ))}
            </div>

            {/* Day columns */}
            {DAY_ABBREVIATIONS.map((_, dayIndex) => {
              const entries = weeklyEntries.get(dayIndex) ?? []
              return (
                <div
                  key={dayIndex}
                  className="relative border-l border-border/40"
                  style={{ height: `${GRID_TOTAL_HOURS * 28}px` }}
                >
                  {/* Hour grid lines */}
                  {hourLabels.slice(0, -1).map((hour) => (
                    <div
                      key={hour}
                      className="absolute left-0 right-0 border-b border-border/20"
                      style={{ top: `${(hour - GRID_START_HOUR) * 28}px`, height: "28px" }}
                    />
                  ))}

                  {/* Entry blocks */}
                  {entries.map((entry) => {
                    if (entry.isClosed) {
                      return (
                        <Tooltip key={entry.id}>
                          <TooltipTrigger asChild>
                            <div
                              className="absolute inset-x-0.5 rounded-sm border border-red-200 bg-red-50 dark:border-red-900/40 dark:bg-red-950/20"
                              style={{
                                top: 0,
                                height: `${GRID_TOTAL_HOURS * 28}px`,
                              }}
                            >
                              <span className="block px-1 pt-0.5 text-[9px] font-medium text-red-500 dark:text-red-400">
                                Closed
                              </span>
                            </div>
                          </TooltipTrigger>
                          <TooltipContent side="top">
                            <p>{DAY_NAMES[dayIndex]} - Closed all day</p>
                          </TooltipContent>
                        </Tooltip>
                      )
                    }

                    const start = parseTime(entry.startTime)
                    const end = parseTime(entry.endTime)

                    // Clamp to visible grid range
                    const clampedStart = Math.max(start, GRID_START_HOUR)
                    const clampedEnd = Math.min(end, GRID_END_HOUR)

                    if (clampedEnd <= clampedStart) return null

                    const topPx = (clampedStart - GRID_START_HOUR) * 28
                    const heightPx = (clampedEnd - clampedStart) * 28

                    return (
                      <Tooltip key={entry.id}>
                        <TooltipTrigger asChild>
                          <div
                            className="absolute inset-x-0.5 rounded-sm border border-emerald-200 bg-emerald-100 transition-colors hover:bg-emerald-200 dark:border-emerald-800/50 dark:bg-emerald-900/30 dark:hover:bg-emerald-900/50"
                            style={{ top: `${topPx}px`, height: `${heightPx}px` }}
                          >
                            {heightPx >= 20 && (
                              <span className="block px-1 pt-0.5 text-[9px] font-medium text-emerald-700 dark:text-emerald-300">
                                {entry.startTime} - {entry.endTime}
                              </span>
                            )}
                          </div>
                        </TooltipTrigger>
                        <TooltipContent side="top">
                          <p>
                            {DAY_NAMES[dayIndex]}: {entry.startTime} - {entry.endTime}
                          </p>
                        </TooltipContent>
                      </Tooltip>
                    )
                  })}
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </TooltipProvider>
  )
}

// -- Main page ----------------------------------------------------------------

function ScheduleDetailPage() {
  const { scheduleId } = Route.useParams()
  const { tab = "list", edit: editParam } = Route.useSearch()
  const navigate = Route.useNavigate()
  const router = useRouter()

  const { data, isLoading, isError, refetch } = useSchedule(scheduleId)
  const updateSchedule = useUpdateSchedule(scheduleId)
  const deleteSchedule = useDeleteSchedule()

  const [editing, setEditing] = useState(false)
  const [editName, setEditName] = useState("")
  const [editTimezone, setEditTimezone] = useState("")
  const [editType, setEditType] = useState<Schedule["scheduleType"]>("business_hours")
  const [editDefault, setEditDefault] = useState(false)
  const [showDeleteFromMenu, setShowDeleteFromMenu] = useState(false)

  useDocumentTitle(data?.name ? `${data.name} - Schedule` : "Schedule")

  useEffect(() => {
    if (editParam && data && !editing) {
      startEditing(data)
      navigate({ search: (prev) => ({ ...prev, edit: undefined }), replace: true })
    }
  }, [editParam, data])

  function startEditing(schedule: Schedule) {
    setEditName(schedule.name)
    setEditTimezone(schedule.timezone)
    setEditType(schedule.scheduleType)
    setEditDefault(schedule.isDefault)
    setEditing(true)
  }

  function handleSave() {
    const payload: Record<string, unknown> = {}
    if (editName !== data?.name) payload.name = editName
    if (editTimezone !== data?.timezone) payload.timezone = editTimezone
    if (editType !== data?.scheduleType) payload.scheduleType = editType
    if (editDefault !== data?.isDefault) payload.isDefault = editDefault
    updateSchedule.mutate(payload, {
      onSuccess: () => setEditing(false),
    })
  }

  const handleDelete = async () => {
    await deleteSchedule.mutateAsync(scheduleId)
    router.navigate({ to: "/schedules" })
  }

  // Organize entries by type
  const weeklyEntries = useMemo(() => {
    if (!data?.entries) return new Map<number, ScheduleEntry[]>()
    const map = new Map<number, ScheduleEntry[]>()
    for (const entry of data.entries) {
      if (entry.dayOfWeek != null) {
        const existing = map.get(entry.dayOfWeek) ?? []
        existing.push(entry)
        map.set(entry.dayOfWeek, existing)
      }
    }
    return map
  }, [data?.entries])

  const holidayEntries = useMemo(() => {
    if (!data?.entries) return []
    return data.entries
      .filter((e) => e.date != null)
      .sort((a, b) => (a.date ?? "").localeCompare(b.date ?? ""))
  }, [data?.entries])

  const showHolidays = data && (data.scheduleType === "holiday" || data.scheduleType === "custom")

  // -- Loading state --

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <div className="space-y-2">
          <Skeleton className="h-4 w-28" />
          <Skeleton className="h-8 w-52" />
          <Skeleton className="h-4 w-64" />
        </div>
        <PageSection>
          <div className="grid gap-6 md:grid-cols-[1.1fr_0.9fr]">
            <div className="space-y-6">
              <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
                <Skeleton className="h-6 w-40" />
                <div className="grid gap-4 md:grid-cols-2">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <div key={i} className="space-y-1.5">
                      <Skeleton className="h-3.5 w-20" />
                      <Skeleton className="h-5 w-36" />
                    </div>
                  ))}
                </div>
              </div>
              <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
                <Skeleton className="h-6 w-32" />
                {Array.from({ length: 7 }).map((_, i) => (
                  <div key={i} className="flex items-center gap-4">
                    <Skeleton className="h-5 w-24" />
                    <Skeleton className="h-5 w-40" />
                  </div>
                ))}
              </div>
            </div>
            <div className="space-y-4">
              <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
                <Skeleton className="h-5 w-24" />
                {Array.from({ length: 3 }).map((_, i) => (
                  <div key={i} className="space-y-1">
                    <Skeleton className="h-3 w-20" />
                    <Skeleton className="h-5 w-40" />
                  </div>
                ))}
              </div>
            </div>
          </div>
        </PageSection>
      </PageContainer>
    )
  }

  // -- Error state --

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Schedules"
          title="Schedule Details"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/schedules">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to schedules
              </Link>
            </Button>
          }
        />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load schedule"
            description="Something went wrong. Please try again."
            action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
          />
        </PageSection>
      </PageContainer>
    )
  }

  // -- Loaded state --

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Schedules"
        title={data.name}
        description={`${scheduleTypeLabels[data.scheduleType] ?? data.scheduleType} schedule`}
        breadcrumbs={
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
                  <Link to="/schedules">Schedules</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>{data.name}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-3">
            <CurrentStatusBadge scheduleId={scheduleId} />
            {data.isDefault && (
              <Badge className="gap-1 bg-blue-100 text-blue-700 hover:bg-blue-100 dark:bg-blue-900/30 dark:text-blue-400">
                Default
              </Badge>
            )}
            {!editing && (
              <Button variant="outline" size="sm" onClick={() => startEditing(data)}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
              </Button>
            )}
            <Button variant="outline" size="sm" asChild>
              <Link to="/schedules">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <MoreHorizontal className="h-4 w-4" />
                  <span className="sr-only">Actions</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => { navigator.clipboard.writeText(scheduleId); toast.success("Copied schedule ID") }}>
                  <Copy className="mr-2 h-4 w-4" />
                  Copy Schedule ID
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem variant="destructive" onClick={() => setShowDeleteFromMenu(true)}>
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete Schedule
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        }
      />

      {/* Delete dialog triggered from dropdown menu */}
      <DeleteScheduleDialog
        scheduleName={data.name}
        onDelete={handleDelete}
        isPending={deleteSchedule.isPending}
        open={showDeleteFromMenu}
        onOpenChange={setShowDeleteFromMenu}
      />

      <PageSection>
        <div className="grid gap-6 md:grid-cols-[1.1fr_0.9fr]">
          {/* Main column */}
          <div className="space-y-6">
            {/* Schedule Information */}
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <Clock className="h-5 w-5 text-muted-foreground" />
                  Schedule Information
                </CardTitle>
                {editing && (
                  <div className="flex gap-2">
                    <Button variant="ghost" size="sm" onClick={() => setEditing(false)}>
                      Cancel
                    </Button>
                    <Button size="sm" onClick={handleSave} disabled={updateSchedule.isPending}>
                      {updateSchedule.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                      Save
                    </Button>
                  </div>
                )}
              </CardHeader>
              <CardContent className="space-y-4">
                {editing ? (
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label>Name</Label>
                      <Input value={editName} onChange={(e) => setEditName(e.target.value)} />
                    </div>
                    <div className="space-y-2">
                      <Label>Type</Label>
                      <Select value={editType} onValueChange={(v) => setEditType(v as Schedule["scheduleType"])}>
                        <SelectTrigger>
                          <SelectValue placeholder="Select type" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="business_hours">Business Hours</SelectItem>
                          <SelectItem value="holiday">Holiday</SelectItem>
                          <SelectItem value="custom">Custom</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>Timezone</Label>
                      <Select value={editTimezone} onValueChange={setEditTimezone}>
                        <SelectTrigger>
                          <SelectValue placeholder="Select timezone" />
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
                    <div className="flex items-center gap-3">
                      <Switch checked={editDefault} onCheckedChange={setEditDefault} id="edit-default" />
                      <Label htmlFor="edit-default">Default schedule</Label>
                    </div>
                  </div>
                ) : (
                  <div className="grid gap-4 text-sm md:grid-cols-2">
                    <InfoField label="Name" value={data.name} />
                    <InfoField label="Type" value={scheduleTypeLabels[data.scheduleType] ?? data.scheduleType} />
                    <InfoField label="Timezone" value={data.timezone.replace(/_/g, " ")} />
                    <InfoField label="Default" value={data.isDefault ? "Yes" : "No"} />
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Weekly Hours */}
            {(data.scheduleType === "business_hours" || data.scheduleType === "custom") && (
              <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Calendar className="h-5 w-5 text-muted-foreground" />
                    Weekly Hours
                  </CardTitle>
                  <CardDescription>Define operating hours for each day of the week.</CardDescription>
                </CardHeader>
                <CardContent>
                  <Tabs value={tab} onValueChange={(value) => navigate({ search: () => ({ tab: value }), replace: true })}>
                    <TabsList className="mb-4">
                      <TabsTrigger value="list" className="gap-1.5">
                        <List className="h-3.5 w-3.5" />
                        List
                      </TabsTrigger>
                      <TabsTrigger value="weekly" className="gap-1.5">
                        <Grid3x3 className="h-3.5 w-3.5" />
                        Weekly View
                      </TabsTrigger>
                    </TabsList>

                    <TabsContent value="list">
                      <div className="overflow-x-auto">
                      <Table aria-label="Weekly schedule entries">
                        <TableHeader>
                          <TableRow>
                            <TableHead className="w-32">Day</TableHead>
                            <TableHead>Hours</TableHead>
                            <TableHead className="w-32 text-right">Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {DAY_NAMES.map((day, index) => {
                            const entries = weeklyEntries.get(index) ?? []
                            return (
                              <TableRow key={index}>
                                <TableCell className="font-medium">{day}</TableCell>
                                <TableCell>
                                  {entries.length === 0 ? (
                                    <span className="text-sm text-muted-foreground">No hours set</span>
                                  ) : (
                                    <div className="flex flex-col gap-1">
                                      {entries.map((entry) => (
                                        <EntryDisplay key={entry.id} entry={entry} scheduleId={scheduleId} />
                                      ))}
                                    </div>
                                  )}
                                </TableCell>
                                <TableCell className="text-right">
                                  <AddWeeklyEntryRow scheduleId={scheduleId} dayOfWeek={index} />
                                </TableCell>
                              </TableRow>
                            )
                          })}
                        </TableBody>
                      </Table>
                      </div>
                    </TabsContent>

                    <TabsContent value="weekly">
                      <WeeklyViewGrid weeklyEntries={weeklyEntries} />
                    </TabsContent>
                  </Tabs>
                </CardContent>
              </Card>
            )}

            {/* Holidays */}
            {showHolidays && (
              <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Calendar className="h-5 w-5 text-muted-foreground" />
                    Holidays
                  </CardTitle>
                  <CardDescription>Define specific dates with special hours or closures.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {holidayEntries.length > 0 ? (
                    <div className="overflow-x-auto">
                    <Table aria-label="Holiday entries">
                      <TableHeader>
                        <TableRow>
                          <TableHead>Date</TableHead>
                          <TableHead>Label</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead className="w-16 text-right">Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {holidayEntries.map((entry) => (
                          <HolidayRow key={entry.id} entry={entry} scheduleId={scheduleId} />
                        ))}
                      </TableBody>
                    </Table>
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground py-4 text-center">No holidays configured.</p>
                  )}
                  <AddHolidayEntry scheduleId={scheduleId} />
                </CardContent>
              </Card>
            )}

            {/* Danger Zone */}
            <Card className="border-destructive/30 bg-card/80 shadow-md">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-destructive">
                  <AlertTriangle className="h-4 w-4" />
                  Danger Zone
                </CardTitle>
                <CardDescription>Irreversible and destructive actions for this schedule.</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between rounded-lg border border-destructive/20 bg-destructive/5 p-4">
                  <div>
                    <p className="font-medium text-sm">Delete this schedule</p>
                    <p className="text-xs text-muted-foreground">
                      Once deleted, this schedule and all entries cannot be recovered.
                    </p>
                  </div>
                  <DeleteScheduleDialog
                    scheduleName={data.name}
                    onDelete={handleDelete}
                    isPending={deleteSchedule.isPending}
                  />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Sidebar */}
          <div className="space-y-4">
            {/* Metadata card */}
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Clock className="h-4 w-4" />
                  Metadata
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground">Schedule ID</p>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs break-all">{data.id}</span>
                    <CopyButton value={data.id} label="schedule ID" />
                  </div>
                </div>
                {data.createdAt && (
                  <div className="space-y-1">
                    <p className="text-xs font-medium text-muted-foreground">Created</p>
                    <p className="text-sm" title={formatDateTime(data.createdAt)}>
                      {formatRelativeTime(data.createdAt)}
                    </p>
                  </div>
                )}
                {data.updatedAt && (
                  <div className="space-y-1">
                    <p className="text-xs font-medium text-muted-foreground">Last Updated</p>
                    <p className="text-sm" title={formatDateTime(data.updatedAt)}>
                      {formatRelativeTime(data.updatedAt)}
                    </p>
                  </div>
                )}
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground">Team ID</p>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs break-all">{data.teamId}</span>
                    <CopyButton value={data.teamId} label="team ID" />
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Quick Stats card */}
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Calendar className="h-4 w-4" />
                  Summary
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Weekly entries</span>
                  <span className="font-medium text-sm">
                    {data.entries?.filter((e) => e.dayOfWeek != null).length ?? 0}
                  </span>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Holiday entries</span>
                  <span className="font-medium text-sm">
                    {data.entries?.filter((e) => e.date != null).length ?? 0}
                  </span>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Total entries</span>
                  <span className="font-medium text-sm">{data.entries?.length ?? 0}</span>
                </div>
              </CardContent>
            </Card>

            {/* Related Resources */}
            <RelatedResourcesSection scheduleId={scheduleId} />

            {/* Activity History (Audit Trail) */}
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Clock className="h-4 w-4" />
                  Activity History
                </CardTitle>
              </CardHeader>
              <CardContent>
                <EntityActivityPanel targetType="schedule" targetId={scheduleId} />
              </CardContent>
            </Card>
          </div>
        </div>
      </PageSection>
    </PageContainer>
  )
}

// -- Related Resources --------------------------------------------------------

function RelatedResourcesSection({ scheduleId }: { scheduleId: string }) {
  const timeConditionsQuery = useTimeConditions({ pageSize: 100 })

  const linkedTimeConditions = (timeConditionsQuery.data?.items ?? []).filter(
    (tc) => tc.scheduleId === scheduleId,
  )

  const isLoading = timeConditionsQuery.isLoading
  const hasTimeConditions = linkedTimeConditions.length > 0

  if (isLoading) {
    return (
      <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Link2 className="h-4 w-4" />
            Related Resources
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {Array.from({ length: 2 }).map((_, i) => (
              <div key={i} className="rounded-lg border border-border/40 p-4 space-y-2">
                <Skeleton className="h-4 w-24" />
                <Skeleton className="h-4 w-36" />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    )
  }

  if (!hasTimeConditions) {
    return (
      <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Link2 className="h-4 w-4" />
            Related Resources
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center gap-2 py-6 text-center">
            <Link2 className="h-8 w-8 text-muted-foreground/50" />
            <p className="text-sm text-muted-foreground">
              No time conditions are currently using this schedule.
            </p>
            <p className="text-xs text-muted-foreground/70">
              Schedules are typically referenced by time conditions for call routing rules.
            </p>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Link2 className="h-4 w-4" />
          Related Resources
        </CardTitle>
        <CardDescription>
          Entities using this schedule for call routing
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Time Conditions
          </p>
          <div className="space-y-2">
            {linkedTimeConditions.map((tc) => (
              <Link
                key={tc.id}
                to="/call-routing/time-conditions/$timeConditionId"
                params={{ timeConditionId: tc.id }}
                className="group flex items-center justify-between rounded-lg border border-border/40 p-3 transition-all hover:bg-muted/30 hover:shadow-sm"
              >
                <div className="flex items-center gap-3">
                  <Clock className="h-4 w-4 text-primary" />
                  <div>
                    <p className="text-sm font-medium group-hover:text-primary">{tc.name}</p>
                    <p className="text-xs text-muted-foreground">
                      Override: {tc.overrideMode}
                    </p>
                  </div>
                </div>
                <ArrowRight className="h-4 w-4 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-foreground" />
              </Link>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

// -- Holiday Row --------------------------------------------------------------

function HolidayRow({ entry, scheduleId }: { entry: ScheduleEntry; scheduleId: string }) {
  const deleteEntry = useDeleteScheduleEntry(scheduleId)
  const [confirmDelete, setConfirmDelete] = useState(false)

  const handleDelete = () => {
    deleteEntry.mutate(entry.id, {
      onSuccess: () => setConfirmDelete(false),
    })
  }

  return (
    <TableRow>
      <TableCell className="font-medium">{entry.date}</TableCell>
      <TableCell>
        <span className="text-sm">{entry.label ?? "--"}</span>
      </TableCell>
      <TableCell>
        {entry.isClosed ? (
          <Badge variant="outline" className="text-xs">
            Closed
          </Badge>
        ) : (
          <span className="text-sm">
            {entry.startTime} - {entry.endTime}
          </span>
        )}
      </TableCell>
      <TableCell className="text-right">
        <Button
          variant="ghost"
          size="sm"
          className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
          onClick={() => setConfirmDelete(true)}
          disabled={deleteEntry.isPending}
        >
          {deleteEntry.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
        </Button>
        <AlertDialog open={confirmDelete} onOpenChange={(open) => !open && setConfirmDelete(false)}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-destructive" />
                Delete holiday entry?
              </AlertDialogTitle>
              <AlertDialogDescription>
                This will permanently remove the holiday entry{entry.label ? ` "${entry.label}"` : ""}{entry.date ? ` on ${entry.date}` : ""}. This action cannot be undone.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel disabled={deleteEntry.isPending}>Cancel</AlertDialogCancel>
              <AlertDialogAction
                className={buttonVariants({ variant: "destructive" })}
                onClick={handleDelete}
                disabled={deleteEntry.isPending}
              >
                {deleteEntry.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {deleteEntry.isPending ? "Deleting..." : "Delete"}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </TableCell>
    </TableRow>
  )
}

// -- Info Field helper --------------------------------------------------------

function InfoField({
  label,
  value,
  mono,
}: {
  label: string
  value?: string | null
  mono?: boolean
}) {
  return (
    <div>
      <p className="text-muted-foreground">{label}</p>
      <p className={mono ? "font-mono text-xs" : ""}>{value ?? "---"}</p>
    </div>
  )
}
