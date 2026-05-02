import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useState } from "react"
import {
  AlertCircle,
  Download,
  Eye,
  Home,
  ListTodo,
  MoreVertical,
  XCircle,
} from "lucide-react"
import { toast } from "sonner"
import { TaskStatusBadge } from "@/components/tasks/task-status-badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
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
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useTasks, useCancelTask, type UseTasksOptions } from "@/lib/api/hooks/tasks"
import type { BackgroundTaskList } from "@/lib/generated/api/types.gen"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { useDocumentTitle } from "@/hooks/use-document-title"

export const Route = createFileRoute("/_app/tasks/")({
  component: TasksPage,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZE = 25

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

const csvHeaders: CsvHeader<BackgroundTaskList>[] = [
  { label: "ID", accessor: (t) => t.id },
  { label: "Task Type", accessor: (t) => t.taskType },
  { label: "Status", accessor: (t) => t.status },
  { label: "Progress", accessor: (t) => (t.progress != null ? `${t.progress}%` : "") },
  { label: "Entity Type", accessor: (t) => t.entityType ?? "" },
  { label: "Entity ID", accessor: (t) => t.entityId ?? "" },
  { label: "Initiated By", accessor: (t) => t.initiatedByName ?? "" },
  { label: "Started", accessor: (t) => (t.startedAt ? formatDateTime(t.startedAt) : "") },
  { label: "Completed", accessor: (t) => (t.completedAt ? formatDateTime(t.completedAt) : "") },
  { label: "Created", accessor: (t) => (t.createdAt ? formatDateTime(t.createdAt) : "") },
]

// -- Helpers ------------------------------------------------------------------

function formatTaskType(taskType: string): string {
  return taskType
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

function formatEntityType(entityType: string | null | undefined): string {
  if (!entityType) return "--"
  return entityType
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

// -- Task Row -----------------------------------------------------------------

function TaskRow({
  task,
  index,
  selected,
  onToggle,
  onRowClick,
}: {
  task: BackgroundTaskList
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
}) {
  const cancelMutation = useCancelTask()
  const isActive = task.status === "pending" || task.status === "running"

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
        <Link
          to="/tasks/$taskId"
          params={{ taskId: task.id }}
          className="group flex flex-col gap-0.5"
          onClick={(e) => e.stopPropagation()}
        >
          <span className="font-medium group-hover:underline text-sm">
            {formatTaskType(task.taskType)}
          </span>
          {task.initiatedByName && (
            <span className="text-xs text-muted-foreground">by {task.initiatedByName}</span>
          )}
        </Link>
      </TableCell>
      <TableCell>
        <TaskStatusBadge status={task.status} />
      </TableCell>
      <TableCell>
        {task.progress != null && task.progress > 0 ? (
          <div className="flex items-center gap-2 min-w-[100px]">
            <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
              <div
                className={`h-full rounded-full transition-all duration-300 ${
                  task.status === "failed"
                    ? "bg-red-500"
                    : task.status === "completed"
                      ? "bg-green-500"
                      : "bg-blue-500"
                }`}
                style={{ width: `${Math.min(task.progress, 100)}%` }}
              />
            </div>
            <span className="text-xs font-medium text-muted-foreground w-8 text-right">
              {Math.round(task.progress)}%
            </span>
          </div>
        ) : (
          <span className="text-xs text-muted-foreground">--</span>
        )}
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <span className="text-sm">{formatEntityType(task.entityType)}</span>
      </TableCell>
      <TableCell className="hidden md:table-cell">
        {task.startedAt ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="cursor-default text-xs text-muted-foreground">
                {formatRelativeTimeShort(task.startedAt)}
              </span>
            </TooltipTrigger>
            <TooltipContent>{formatDateTime(task.startedAt)}</TooltipContent>
          </Tooltip>
        ) : (
          <span className="text-xs text-muted-foreground">--</span>
        )}
      </TableCell>
      <TableCell className="hidden md:table-cell">
        {task.completedAt ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="cursor-default text-xs text-muted-foreground">
                {formatRelativeTimeShort(task.completedAt)}
              </span>
            </TooltipTrigger>
            <TooltipContent>{formatDateTime(task.completedAt)}</TooltipContent>
          </Tooltip>
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
                <DropdownMenuItem
                  variant="destructive"
                  disabled={cancelMutation.isPending}
                  onClick={() => cancelMutation.mutate(task.id)}
                >
                  <XCircle className="mr-2 h-4 w-4" />
                  Cancel task
                </DropdownMenuItem>
              </>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  )
}

// -- Main page ----------------------------------------------------------------

function TasksPage() {
  useDocumentTitle("Background Tasks")

  const navigate = useNavigate()

  const [statusFilter, setStatusFilter] = useState("all")
  const [taskTypeFilter, setTaskTypeFilter] = useState("all")
  const [page, setPage] = useState(1)

  // Reset page when filters change
  useEffect(() => {
    setPage(1)
  }, [statusFilter, taskTypeFilter])

  const queryOptions: UseTasksOptions = useMemo(
    () => ({
      page,
      pageSize: PAGE_SIZE,
      status: statusFilter !== "all" ? statusFilter : undefined,
      taskType: taskTypeFilter !== "all" ? taskTypeFilter : undefined,
      orderBy: "created_at",
      sortOrder: "desc" as const,
    }),
    [page, statusFilter, taskTypeFilter],
  )

  const { data, isLoading, isError, refetch } = useTasks(queryOptions)

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

  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE))
  const hasData = items.length > 0
  const hasAnyFilters = statusFilter !== "all" || taskTypeFilter !== "all"

  const clearAllFilters = useCallback(() => {
    setStatusFilter("all")
    setTaskTypeFilter("all")
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
    exportToCsv("background-tasks", csvHeaders, items)
    toast.success(`Exported ${items.length} task${items.length === 1 ? "" : "s"}`)
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
          <BreadcrumbPage>Tasks</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="System"
        title="Background Tasks"
        description="Monitor and manage background tasks such as bulk imports, exports, and syncs."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!hasData}>
              <Download className="mr-1.5 h-3.5 w-3.5" />
              Export
            </Button>
          </div>
        }
      />

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
          {hasAnyFilters && (
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
            description="Background tasks will appear here when bulk operations, imports, exports, or syncs are initiated."
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
              <Table aria-label="Background tasks">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all tasks"
                      />
                    </TableHead>
                    <TableHead>Task Type</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Progress</TableHead>
                    <TableHead className="hidden md:table-cell">Entity</TableHead>
                    <TableHead className="hidden md:table-cell">Started</TableHead>
                    <TableHead className="hidden md:table-cell">Completed</TableHead>
                    <TableHead className="w-16 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((task, index) => (
                    <TaskRow
                      key={task.id}
                      task={task}
                      index={index}
                      selected={selectedIds.has(task.id)}
                      onToggle={() => toggleOne(task.id)}
                      onRowClick={() => handleRowClick(task.id)}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between pt-2">
                <p className="text-xs text-muted-foreground">
                  {data!.total} total task{data!.total === 1 ? "" : "s"}
                </p>
                <div className="flex gap-2">
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
              </div>
            )}
          </div>
        )}
      </PageSection>
    </PageContainer>
  )
}
