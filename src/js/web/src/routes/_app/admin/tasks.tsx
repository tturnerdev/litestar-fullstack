import { useQueryClient } from "@tanstack/react-query"
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import {
  AlertCircle,
  Calendar,
  CalendarDays,
  CheckCircle2,
  Clock,
  Download,
  Eye,
  ListTodo,
  Loader2,
  MoreVertical,
  Pause,
  SlidersHorizontal,
  Timer,
  Trash2,
  XCircle,
} from "lucide-react"
import { useCallback, useEffect, useMemo, useState } from "react"
import { toast } from "sonner"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { TaskStatusBadge } from "@/components/tasks/task-status-badge"
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
import { type BulkAction, BulkActionBar } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { DataFreshness } from "@/components/ui/data-freshness"
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
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { type AdminTaskSummary, type AdminTasksParams, useAdminCancelTask, useAdminDeleteTask, useAdminTaskStats, useAdminTasks } from "@/lib/api/hooks/admin"
import { type CsvHeader, exportToCsv } from "@/lib/csv-export"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"

export const Route = createFileRoute("/_app/admin/tasks")({
  component: AdminTasksPage,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_STORAGE_KEY = "admin-tasks-page-size"

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

const statusFilterOptions = [
  { value: "all", label: "All Statuses" },
  { value: "pending", label: "Pending" },
  { value: "running", label: "Running" },
  { value: "completed", label: "Completed" },
  { value: "failed", label: "Failed" },
  { value: "cancelled", label: "Cancelled" },
]

const taskTypeFilterOptions = [
  { value: "all", label: "All Types" },
  { value: "bulk_import", label: "Bulk Import" },
  { value: "bulk_export", label: "Bulk Export" },
  { value: "bulk_delete", label: "Bulk Delete" },
  { value: "sync", label: "Sync" },
  { value: "report", label: "Report" },
]

const entityTypeFilterOptions = [
  { value: "all", label: "All Entities" },
  { value: "device", label: "Device" },
  { value: "extension", label: "Extension" },
  { value: "phone_number", label: "Phone Number" },
  { value: "fax_number", label: "Fax Number" },
  { value: "fax_message", label: "Fax Message" },
  { value: "user", label: "User" },
  { value: "team", label: "Team" },
  { value: "ticket", label: "Ticket" },
]

const csvHeaders: CsvHeader<AdminTaskSummary>[] = [
  { label: "ID", accessor: (t) => t.id },
  { label: "Task Type", accessor: (t) => t.taskType },
  { label: "Status", accessor: (t) => t.status },
  { label: "Progress", accessor: (t) => (t.progress != null ? `${t.progress}%` : "") },
  { label: "Entity Type", accessor: (t) => t.entityType ?? "" },
  { label: "Entity ID", accessor: (t) => t.entityId ?? "" },
  { label: "Initiated By", accessor: (t) => t.initiatedByName ?? "" },
  { label: "Team", accessor: (t) => t.teamName ?? "" },
  { label: "Started", accessor: (t) => (t.startedAt ? formatDateTime(t.startedAt) : "") },
  { label: "Completed", accessor: (t) => (t.completedAt ? formatDateTime(t.completedAt) : "") },
  { label: "Created", accessor: (t) => (t.createdAt ? formatDateTime(t.createdAt) : "") },
]

const COLUMN_VISIBILITY_KEY = "admin-tasks-columns"

const TOGGLEABLE_COLUMNS = [
  { key: "progress", label: "Progress" },
  { key: "team", label: "Team" },
  { key: "entity", label: "Entity" },
  { key: "started", label: "Started" },
  { key: "completed", label: "Completed" },
] as const

type ColumnVisibility = Record<string, boolean>

function loadColumnVisibility(): ColumnVisibility {
  try {
    return JSON.parse(localStorage.getItem(COLUMN_VISIBILITY_KEY) ?? "{}")
  } catch {
    return {}
  }
}

// -- Helpers ------------------------------------------------------------------

function formatTaskType(taskType: string): string {
  return taskType.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())
}

function formatEntityType(entityType: string | null | undefined): string {
  if (!entityType) return "--"
  return entityType.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())
}

// -- Stats Summary ------------------------------------------------------------

const STATUS_CONFIG: Record<string, { label: string; icon: React.ReactNode; className: string }> = {
  pending: { label: "Pending", icon: <Pause className="h-3.5 w-3.5" />, className: "text-yellow-600 dark:text-yellow-400" },
  running: { label: "Running", icon: <Loader2 className="h-3.5 w-3.5 animate-spin" />, className: "text-blue-600 dark:text-blue-400" },
  completed: { label: "Completed", icon: <CheckCircle2 className="h-3.5 w-3.5" />, className: "text-green-600 dark:text-green-400" },
  failed: { label: "Failed", icon: <AlertCircle className="h-3.5 w-3.5" />, className: "text-red-600 dark:text-red-400" },
  cancelled: { label: "Cancelled", icon: <XCircle className="h-3.5 w-3.5" />, className: "text-muted-foreground" },
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(1)}s`
  const mins = Math.floor(seconds / 60)
  const secs = Math.round(seconds % 60)
  return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`
}

function TaskStatsSummary() {
  const { data: stats, isLoading } = useAdminTaskStats()

  if (isLoading) {
    return (
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {["queued", "active", "complete", "failed"].map((id) => (
          <Card key={id}>
            <CardHeader className="pb-2">
              <div className="h-4 w-20 animate-pulse rounded bg-muted" />
            </CardHeader>
            <CardContent>
              <div className="h-7 w-12 animate-pulse rounded bg-muted" />
            </CardContent>
          </Card>
        ))}
      </div>
    )
  }

  if (!stats) return null

  const totalAll = Object.values(stats.byStatus).reduce((sum, n) => sum + n, 0)
  const topDurations = Object.entries(stats.avgDurationSeconds)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 3)

  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {/* Total tasks card */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Total Tasks</CardTitle>
          <ListTodo className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{totalAll.toLocaleString()}</div>
          <div className="mt-1 flex items-center gap-3 text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <Calendar className="h-3 w-3" />
              {stats.totalToday} today
            </span>
            <span className="flex items-center gap-1">
              <CalendarDays className="h-3 w-3" />
              {stats.totalThisWeek} this week
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Status breakdown card */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">By Status</CardTitle>
          <Clock className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-x-3 gap-y-1">
            {Object.entries(STATUS_CONFIG).map(([key, cfg]) => {
              const count = stats.byStatus[key] ?? 0
              if (count === 0 && key !== "running" && key !== "pending") return null
              return (
                <span key={key} className={`flex items-center gap-1 text-sm ${cfg.className}`}>
                  {cfg.icon}
                  <span className="font-semibold">{count}</span>
                  <span className="text-xs">{cfg.label}</span>
                </span>
              )
            })}
          </div>
        </CardContent>
      </Card>

      {/* Active tasks card */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Active</CardTitle>
          <Loader2 className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{((stats.byStatus.pending ?? 0) + (stats.byStatus.running ?? 0)).toLocaleString()}</div>
          <div className="mt-1 flex items-center gap-3 text-xs text-muted-foreground">
            <span>{stats.byStatus.pending ?? 0} pending</span>
            <span>{stats.byStatus.running ?? 0} running</span>
          </div>
        </CardContent>
      </Card>

      {/* Avg duration card */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Avg Duration</CardTitle>
          <Timer className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          {topDurations.length > 0 ? (
            <div className="space-y-1">
              {topDurations.map(([taskType, seconds]) => (
                <div key={taskType} className="flex items-center justify-between text-sm">
                  <span className="truncate text-muted-foreground">{formatTaskType(taskType)}</span>
                  <span className="ml-2 font-medium tabular-nums">{formatDuration(seconds)}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No data yet</p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

// -- Task Row -----------------------------------------------------------------

function AdminTaskRow({
  task,
  index,
  selected,
  onToggle,
  onRowClick,
  isColumnVisible,
}: {
  task: AdminTaskSummary
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
  isColumnVisible: (col: string) => boolean
}) {
  const cancelMutation = useAdminCancelTask()
  const deleteMutation = useAdminDeleteTask()
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const isActive = task.status === "pending" || task.status === "running"
  const isTerminal = task.status === "completed" || task.status === "failed" || task.status === "cancelled"

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
          aria-label={`Select task ${task.id}`}
        />
      </TableCell>
      <TableCell>
        <Link to="/tasks/$taskId" params={{ taskId: task.id }} className="group flex flex-col gap-0.5" onClick={(e) => e.stopPropagation()}>
          <span className="font-medium group-hover:underline text-sm">{formatTaskType(task.taskType)}</span>
          {task.initiatedByName && <span className="text-xs text-muted-foreground">by {task.initiatedByName}</span>}
        </Link>
      </TableCell>
      <TableCell>
        <TaskStatusBadge status={task.status} />
      </TableCell>
      {isColumnVisible("progress") && (
        <TableCell>
          {task.progress != null && task.progress > 0 ? (
            <div className="flex items-center gap-2 min-w-[100px]">
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
                <div
                  className={`h-full rounded-full transition-all duration-300 ${
                    task.status === "failed" ? "bg-red-500" : task.status === "completed" ? "bg-green-500" : "bg-blue-500"
                  }`}
                  style={{ width: `${Math.min(task.progress, 100)}%` }}
                />
              </div>
              <span className="text-xs font-medium text-muted-foreground w-8 text-right">{Math.round(task.progress)}%</span>
            </div>
          ) : (
            <span className="text-xs text-muted-foreground">--</span>
          )}
        </TableCell>
      )}
      {isColumnVisible("team") && (
        <TableCell>
          <span className="text-sm">{task.teamName ?? "--"}</span>
        </TableCell>
      )}
      {isColumnVisible("entity") && (
        <TableCell>
          <span className="text-sm">{formatEntityType(task.entityType)}</span>
        </TableCell>
      )}
      {isColumnVisible("started") && (
        <TableCell>
          {task.startedAt ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="cursor-default text-xs text-muted-foreground">{formatRelativeTimeShort(task.startedAt)}</span>
              </TooltipTrigger>
              <TooltipContent>{formatDateTime(task.startedAt)}</TooltipContent>
            </Tooltip>
          ) : (
            <span className="text-xs text-muted-foreground">--</span>
          )}
        </TableCell>
      )}
      {isColumnVisible("completed") && (
        <TableCell>
          {task.completedAt ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="cursor-default text-xs text-muted-foreground">{formatRelativeTimeShort(task.completedAt)}</span>
              </TooltipTrigger>
              <TooltipContent>{formatDateTime(task.completedAt)}</TooltipContent>
            </Tooltip>
          ) : (
            <span className="text-xs text-muted-foreground">--</span>
          )}
        </TableCell>
      )}
      <TableCell className="text-right">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" className="h-8 w-8 p-0" data-slot="dropdown" onClick={(e) => e.stopPropagation()}>
              <MoreVertical className="h-4 w-4" />
              <span className="sr-only">Actions for task {task.id}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link to="/tasks/$taskId" params={{ taskId: task.id }}>
                <Eye className="mr-2 h-4 w-4" />
                View details
              </Link>
            </DropdownMenuItem>
            {isActive && (
              <>
                <DropdownMenuSeparator />
                <DropdownMenuItem variant="destructive" disabled={cancelMutation.isPending} onClick={() => cancelMutation.mutate(task.id)}>
                  <XCircle className="mr-2 h-4 w-4" />
                  Cancel task
                </DropdownMenuItem>
              </>
            )}
            {isTerminal && (
              <>
                <DropdownMenuSeparator />
                <DropdownMenuItem variant="destructive" onClick={() => setShowDeleteDialog(true)}>
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete task
                </DropdownMenuItem>
              </>
            )}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Delete confirmation dialog */}
        <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Delete task</AlertDialogTitle>
              <AlertDialogDescription>Are you sure you want to delete this task? This action cannot be undone.</AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel disabled={deleteMutation.isPending}>Cancel</AlertDialogCancel>
              <AlertDialogAction
                onClick={() => {
                  deleteMutation.mutate(task.id, {
                    onSuccess: () => setShowDeleteDialog(false),
                  })
                }}
                disabled={deleteMutation.isPending}
                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              >
                {deleteMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Delete
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </TableCell>
    </TableRow>
  )
}

// -- Main page ----------------------------------------------------------------

function AdminTasksPage() {
  useDocumentTitle("Admin Tasks")

  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const adminCancelTask = useAdminCancelTask()
  const adminDeleteTask = useAdminDeleteTask()

  const [statusFilter, setStatusFilter] = useState("all")
  const [taskTypeFilter, setTaskTypeFilter] = useState("all")
  const [entityTypeFilter, setEntityTypeFilter] = useState("all")
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(getStoredPageSize)

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

  // Column visibility
  const [columnVisibility, setColumnVisibility] = useState<ColumnVisibility>(loadColumnVisibility)
  const isColumnVisible = useCallback((col: string) => columnVisibility[col] !== false, [columnVisibility])
  const toggleColumn = useCallback((col: string) => {
    setColumnVisibility((prev) => {
      const updated = { ...prev, [col]: prev[col] !== false ? false : true }
      localStorage.setItem(COLUMN_VISIBILITY_KEY, JSON.stringify(updated))
      return updated
    })
  }, [])

  // Reset page when filters change
  useEffect(() => {
    setPage(1)
  }, [statusFilter, taskTypeFilter, entityTypeFilter])

  const queryOptions: AdminTasksParams = useMemo(
    () => ({
      page,
      pageSize,
      status: statusFilter !== "all" ? statusFilter : undefined,
      taskType: taskTypeFilter !== "all" ? taskTypeFilter : undefined,
      entityType: entityTypeFilter !== "all" ? entityTypeFilter : undefined,
      orderBy: "created_at",
      sortOrder: "desc" as const,
    }),
    [page, pageSize, statusFilter, taskTypeFilter, entityTypeFilter],
  )

  const { data, isLoading, isError, refetch, dataUpdatedAt, isRefetching } = useAdminTasks(queryOptions)

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  const items = data?.items ?? []

  // Selection helpers
  const allVisibleIds = useMemo(() => items.map((t) => t.id), [items])
  const allSelected = items.length > 0 && items.every((t) => selectedIds.has(t.id))
  const someSelected = items.some((t) => selectedIds.has(t.id))

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

  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / pageSize))
  const hasData = items.length > 0
  const hasAnyFilters = statusFilter !== "all" || taskTypeFilter !== "all" || entityTypeFilter !== "all"

  const clearAllFilters = useCallback(() => {
    setStatusFilter("all")
    setTaskTypeFilter("all")
    setEntityTypeFilter("all")
    setPage(1)
  }, [])

  const handleRowClick = useCallback(
    (taskId: string) => {
      navigate({ to: "/tasks/$taskId", params: { taskId } })
    },
    [navigate],
  )

  const handleExportAll = useCallback(() => {
    if (!items.length) return
    exportToCsv("admin-tasks", csvHeaders, items)
    toast.success(`Exported ${items.length} task${items.length === 1 ? "" : "s"}`)
  }, [items])

  // Bulk actions
  const bulkActions = useMemo<BulkAction[]>(
    () => [
      {
        key: "cancel",
        label: "Cancel Selected",
        icon: <XCircle className="h-4 w-4" />,
        variant: "outline",
        confirm: {
          title: "Cancel selected tasks?",
          description: "This will cancel all selected pending or running tasks. Tasks that are already completed, failed, or cancelled will be skipped.",
        },
        onExecute: async (ids) => {
          let succeeded = 0
          let skipped = 0
          let failed = 0
          for (const id of ids) {
            const task = items.find((t) => t.id === id)
            if (!task || (task.status !== "pending" && task.status !== "running")) {
              skipped++
              continue
            }
            try {
              await adminCancelTask.mutateAsync(id)
              succeeded++
            } catch {
              failed++
            }
          }
          await queryClient.invalidateQueries({ queryKey: ["admin", "tasks"] })
          setSelectedIds(new Set())
          if (failed === 0 && skipped === 0) {
            toast.success(`Cancelled ${succeeded} task${succeeded !== 1 ? "s" : ""}`)
          } else if (failed === 0) {
            toast.success(`Cancelled ${succeeded} task${succeeded !== 1 ? "s" : ""} (${skipped} skipped)`)
          } else {
            toast.warning(`${succeeded} cancelled, ${failed} failed, ${skipped} skipped`)
          }
        },
      },
      {
        key: "delete",
        label: "Delete Selected",
        icon: <Trash2 className="h-4 w-4" />,
        variant: "destructive",
        confirm: {
          title: "Delete selected tasks?",
          description: "This will permanently delete all selected completed, failed, or cancelled tasks. Active tasks will be skipped.",
        },
        onExecute: async (ids) => {
          let succeeded = 0
          let skipped = 0
          let failed = 0
          for (const id of ids) {
            const task = items.find((t) => t.id === id)
            if (!task || task.status === "pending" || task.status === "running") {
              skipped++
              continue
            }
            try {
              await adminDeleteTask.mutateAsync(id)
              succeeded++
            } catch {
              failed++
            }
          }
          await queryClient.invalidateQueries({ queryKey: ["admin", "tasks"] })
          setSelectedIds(new Set())
          if (failed === 0 && skipped === 0) {
            toast.success(`Deleted ${succeeded} task${succeeded !== 1 ? "s" : ""}`)
          } else if (failed === 0) {
            toast.success(`Deleted ${succeeded} task${succeeded !== 1 ? "s" : ""} (${skipped} skipped)`)
          } else {
            toast.warning(`${succeeded} deleted, ${failed} failed, ${skipped} skipped`)
          }
        },
      },
      {
        key: "export",
        label: "Export Selected",
        icon: <Download className="h-4 w-4" />,
        variant: "outline",
        onExecute: async (ids) => {
          const selected = items.filter((t) => ids.includes(t.id))
          exportToCsv("admin-tasks-selected", csvHeaders, selected)
          toast.success(`Exported ${selected.length} task${selected.length === 1 ? "" : "s"}`)
        },
      },
    ],
    [items, adminCancelTask, adminDeleteTask, queryClient],
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Background Tasks"
        description="Monitor and manage background tasks across all teams."
        breadcrumbs={<AdminBreadcrumbs />}
        actions={
          <div className="flex items-center gap-2">
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
              <Download className="mr-1.5 h-3.5 w-3.5" />
              Export
            </Button>
          </div>
        }
      />
      <AdminNav />

      {/* Stats Summary */}
      <PageSection>
        <SectionErrorBoundary name="Task Statistics">
          <TaskStatsSummary />
        </SectionErrorBoundary>
      </PageSection>

      {/* Filters */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="Filter by status" />
            </SelectTrigger>
            <SelectContent>
              {statusFilterOptions.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={taskTypeFilter} onValueChange={setTaskTypeFilter}>
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="Filter by type" />
            </SelectTrigger>
            <SelectContent>
              {taskTypeFilterOptions.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={entityTypeFilter} onValueChange={setEntityTypeFilter}>
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="Filter by entity" />
            </SelectTrigger>
            <SelectContent>
              {entityTypeFilterOptions.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {hasAnyFilters && (
            <Button variant="ghost" size="sm" className="text-xs text-muted-foreground" onClick={clearAllFilters}>
              Clear all filters
            </Button>
          )}
          <div className="ml-auto">
            <DataFreshness dataUpdatedAt={dataUpdatedAt} onRefresh={() => refetch()} isRefreshing={isRefetching} />
          </div>
        </div>
      </PageSection>

      {/* Content */}
      <PageSection delay={0.1}>
        <SectionErrorBoundary name="Task List">
          {isLoading ? (
            <SkeletonTable rows={6} />
          ) : isError ? (
            <EmptyState
              icon={AlertCircle}
              title="Unable to load tasks"
              description="Something went wrong while fetching background tasks. Please try again."
              action={
                <Button variant="outline" size="sm" onClick={() => refetch()}>
                  Try again
                </Button>
              }
            />
          ) : !hasData && !hasAnyFilters ? (
            <EmptyState
              icon={ListTodo}
              title="No background tasks"
              description="Background tasks will appear here when bulk operations, imports, exports, or syncs are initiated across any team."
            />
          ) : !hasData ? (
            <EmptyState
              icon={ListTodo}
              variant="no-results"
              title="No results found"
              description="No tasks match your current filters. Try adjusting your filters."
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
                  {data?.total ?? items.length} task{(data?.total ?? items.length) === 1 ? "" : "s"}
                  {hasAnyFilters && " (filtered)"}
                </p>
                {totalPages > 1 && (
                  <p className="text-xs text-muted-foreground">
                    Page {page} of {totalPages}
                  </p>
                )}
              </div>

              {/* Table */}
              <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
                <Table aria-label="Admin background tasks">
                  <TableHeader className="sticky top-0 z-10 bg-background">
                    <TableRow>
                      <TableHead className="w-10">
                        <Checkbox checked={allSelected} indeterminate={someSelected && !allSelected} onChange={toggleAll} aria-label="Select all tasks" />
                      </TableHead>
                      <TableHead>Task Type</TableHead>
                      <TableHead>Status</TableHead>
                      {isColumnVisible("progress") && <TableHead>Progress</TableHead>}
                      {isColumnVisible("team") && <TableHead>Team</TableHead>}
                      {isColumnVisible("entity") && <TableHead>Entity</TableHead>}
                      {isColumnVisible("started") && <TableHead>Started</TableHead>}
                      {isColumnVisible("completed") && <TableHead>Completed</TableHead>}
                      <TableHead className="w-16 text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.map((task, index) => (
                      <AdminTaskRow
                        key={task.id}
                        task={task}
                        index={index}
                        selected={selectedIds.has(task.id)}
                        onToggle={() => toggleOne(task.id)}
                        onRowClick={() => handleRowClick(task.id)}
                        isColumnVisible={isColumnVisible}
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
                      onClick={() => {
                        setPage((p) => Math.max(1, p - 1))
                        setSelectedIds(new Set())
                      }}
                      disabled={page <= 1}
                    >
                      Previous
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setPage((p) => Math.min(totalPages, p + 1))
                        setSelectedIds(new Set())
                      }}
                      disabled={page >= totalPages}
                    >
                      Next
                    </Button>
                  </div>
                )}
              </div>
            </div>
          )}
        </SectionErrorBoundary>
      </PageSection>

      {/* Bulk action bar */}
      <BulkActionBar selectedCount={selectedIds.size} selectedIds={Array.from(selectedIds)} onClearSelection={() => setSelectedIds(new Set())} actions={bulkActions} />
    </PageContainer>
  )
}
