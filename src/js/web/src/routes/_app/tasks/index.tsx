import { createFileRoute, Link } from "@tanstack/react-router"
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
import { BulkActionBar, createExportAction, type BulkAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { DataFreshness } from "@/components/ui/data-freshness"
import { EmptyState } from "@/components/ui/empty-state"
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
import { useTasks, useCancelTask, type UseTasksOptions } from "@/lib/api/hooks/tasks"
import type { BackgroundTaskList } from "@/lib/generated/api/types.gen"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { useDocumentTitle } from "@/hooks/use-document-title"

export const Route = createFileRoute("/_app/tasks/")({
  validateSearch: (
    search: Record<string, unknown>,
  ): {
    page?: number
    status?: string
    type?: string
    sort?: string
    order?: string
  } => ({
    page: Number(search.page) > 1 ? Number(search.page) : undefined,
    status:
      typeof search.status === "string" && search.status && search.status !== "all"
        ? search.status
        : undefined,
    type:
      typeof search.type === "string" && search.type && search.type !== "all"
        ? search.type
        : undefined,
    sort: typeof search.sort === "string" && search.sort ? search.sort : undefined,
    order:
      typeof search.order === "string" && (search.order === "asc" || search.order === "desc")
        ? search.order
        : undefined,
  }),
  component: TasksPage,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_STORAGE_KEY = "tasks-page-size"

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

function formatDuration(
  startedAt: string | null | undefined,
  completedAt: string | null | undefined,
  status: string,
): string {
  if (!startedAt) return "--"
  const start = new Date(startedAt).getTime()
  const end = completedAt
    ? new Date(completedAt).getTime()
    : status === "running"
      ? Date.now()
      : start
  const ms = end - start
  if (ms < 1000) return "<1s"
  const seconds = Math.floor(ms / 1000) % 60
  const minutes = Math.floor(ms / 60000) % 60
  const hours = Math.floor(ms / 3600000)
  if (hours > 0) return `${hours}h ${minutes}m`
  if (minutes > 0) return `${minutes}m ${seconds}s`
  return `${seconds}s`
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
        <span className="text-xs text-muted-foreground tabular-nums">
          {formatDuration(task.startedAt, task.completedAt, task.status)}
        </span>
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

  const {
    page: pageParam,
    status: statusParam,
    type: typeParam,
    sort: sortParam,
    order: orderParam,
  } = Route.useSearch()
  const navigate = Route.useNavigate()

  // Derive filter state from URL search params
  const statusFilter = statusParam ?? "all"
  const taskTypeFilter = typeParam ?? "all"
  const page = pageParam ?? 1
  const sortKey = sortParam ?? null
  const sortDir: SortDirection = (orderParam as SortDirection) ?? null

  const [pageSize, setPageSize] = useState(getStoredPageSize)

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

  // Page-level cancel mutation for bulk actions
  const cancelMutation = useCancelTask()

  // Persist page size preference
  const handlePageSizeChange = useCallback(
    (value: string) => {
      const size = Number(value)
      setPageSize(size)
      navigate({ search: (prev) => ({ ...prev, page: undefined }), replace: true })
      try {
        localStorage.setItem(PAGE_SIZE_STORAGE_KEY, value)
      } catch {
        // localStorage unavailable
      }
    },
    [navigate],
  )

  // Track whether active tasks exist for auto-refresh (avoids circular dep)
  const [hasActiveTasks, setHasActiveTasks] = useState(false)

  const queryOptions: UseTasksOptions = useMemo(
    () => ({
      page,
      pageSize,
      status: statusFilter !== "all" ? statusFilter : undefined,
      taskType: taskTypeFilter !== "all" ? taskTypeFilter : undefined,
      orderBy: sortKey ?? "created_at",
      sortOrder: sortDir ?? "desc",
      refetchInterval: hasActiveTasks ? 15000 : false,
    }),
    [page, pageSize, statusFilter, taskTypeFilter, sortKey, sortDir, hasActiveTasks],
  )

  const { data, isLoading, isError, refetch, dataUpdatedAt, isRefetching } = useTasks(queryOptions)

  // Update active-tasks flag when data changes
  useEffect(() => {
    const items = data?.items ?? []
    const active = items.some((t) => t.status === "pending" || t.status === "running")
    setHasActiveTasks(active)
  }, [data?.items])

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  const items = data?.items ?? []

  // Task summary stats
  const taskStats = useMemo(() => {
    let running = 0
    let completed = 0
    let failed = 0
    let pending = 0
    for (const t of items) {
      switch (t.status) {
        case "running":
          running++
          break
        case "completed":
          completed++
          break
        case "failed":
          failed++
          break
        case "pending":
          pending++
          break
      }
    }
    return { total: data?.total ?? 0, running, completed, failed, pending }
  }, [items, data?.total])

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

  // Bulk actions
  const bulkActions = useMemo((): BulkAction[] => [
    createExportAction<BackgroundTaskList>(
      "background-tasks",
      csvHeaders,
      (ids) => items.filter((t) => ids.includes(t.id)),
    ),
    {
      key: "cancel",
      label: "Cancel Selected",
      icon: <XCircle className="h-4 w-4" />,
      variant: "destructive" as const,
      confirm: {
        title: "Cancel selected tasks?",
        description: "Only pending and running tasks will be cancelled. This action cannot be undone.",
      },
      onExecute: async (ids: string[]) => {
        const activeTasks = items.filter(
          (t) => ids.includes(t.id) && (t.status === "pending" || t.status === "running"),
        )
        if (activeTasks.length === 0) {
          toast.info("No active tasks to cancel among the selection")
          return
        }
        const errors: string[] = []
        for (const t of activeTasks) {
          try {
            await cancelMutation.mutateAsync(t.id)
          } catch {
            errors.push(t.id)
          }
        }
        if (errors.length > 0) {
          toast.error(`Failed to cancel ${errors.length} of ${activeTasks.length} tasks`)
        }
        setSelectedIds(new Set())
      },
    },
  ], [items, cancelMutation])

  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / pageSize))
  const hasData = items.length > 0
  const hasAnyFilters = statusFilter !== "all" || taskTypeFilter !== "all"

  const clearAllFilters = useCallback(() => {
    navigate({
      search: (prev) => ({
        ...prev,
        status: undefined,
        type: undefined,
        page: undefined,
      }),
    })
  }, [navigate])

  const handleRowClick = useCallback(
    (taskId: string) => {
      void navigate({ to: "/tasks/$taskId", params: { taskId } })
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
            <DataFreshness
              dataUpdatedAt={dataUpdatedAt}
              onRefresh={() => refetch()}
              isRefreshing={isRefetching}
            />
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!hasData}>
              <Download className="mr-1.5 h-3.5 w-3.5" />
              Export
            </Button>
          </div>
        }
      />

      {/* Summary stats */}
      <div className="flex flex-wrap items-center gap-2">
        {isLoading ? (
          <>
            <Skeleton className="h-7 w-20 rounded-full" />
            <Skeleton className="h-7 w-28 rounded-full" />
            <Skeleton className="h-7 w-28 rounded-full" />
            <Skeleton className="h-7 w-24 rounded-full" />
            <Skeleton className="h-7 w-24 rounded-full" />
          </>
        ) : (
          <>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-muted/50 px-3 py-1 text-xs font-medium text-muted-foreground">
              Total
              <span className="ml-0.5 font-semibold text-foreground">{taskStats.total}</span>
            </span>
            {taskStats.running > 0 && (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 px-3 py-1 text-xs font-medium text-blue-700 dark:text-blue-400">
                <span className="h-1.5 w-1.5 rounded-full bg-blue-500" />
                Running
                <span className="ml-0.5 font-semibold">{taskStats.running}</span>
              </span>
            )}
            {taskStats.completed > 0 && (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-400">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                Completed
                <span className="ml-0.5 font-semibold">{taskStats.completed}</span>
              </span>
            )}
            {taskStats.failed > 0 && (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-red-500/30 bg-red-500/10 px-3 py-1 text-xs font-medium text-red-700 dark:text-red-400">
                <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
                Failed
                <span className="ml-0.5 font-semibold">{taskStats.failed}</span>
              </span>
            )}
            {taskStats.pending > 0 && (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-zinc-400/30 bg-zinc-400/10 px-3 py-1 text-xs font-medium text-zinc-600 dark:text-zinc-400">
                <span className="h-1.5 w-1.5 rounded-full bg-zinc-400" />
                Pending
                <span className="ml-0.5 font-semibold">{taskStats.pending}</span>
              </span>
            )}
          </>
        )}
      </div>

      {/* Filters */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <Select
            value={statusFilter}
            onValueChange={(v) =>
              navigate({
                search: (prev) => ({
                  ...prev,
                  status: v !== "all" ? v : undefined,
                  page: undefined,
                }),
              })
            }
          >
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
          <Select
            value={taskTypeFilter}
            onValueChange={(v) =>
              navigate({
                search: (prev) => ({
                  ...prev,
                  type: v !== "all" ? v : undefined,
                  page: undefined,
                }),
              })
            }
          >
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

            <div className="sr-only" aria-live="polite" aria-atomic="true">
              {!isLoading && `Showing ${items.length} of ${data?.total ?? 0} tasks, page ${page}`}
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
              <Table aria-label="Background tasks" aria-busy={isLoading || isRefetching}>
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
                    <SortableHeader label="Task Type" sortKey="task_type" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />
                    <SortableHeader label="Status" sortKey="status" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />
                    <TableHead>Progress</TableHead>
                    <TableHead className="hidden md:table-cell">Entity</TableHead>
                    <SortableHeader label="Started" sortKey="started_at" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} className="hidden md:table-cell" />
                    <TableHead className="hidden md:table-cell">Duration</TableHead>
                    <SortableHeader label="Completed" sortKey="completed_at" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} className="hidden md:table-cell" />
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
            <div className="flex items-center justify-end gap-4 pt-2">
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
                  </Button>
                </div>
              )}
            </div>
          </div>
        )}
      </PageSection>

      <BulkActionBar
        selectedCount={selectedIds.size}
        selectedIds={Array.from(selectedIds)}
        onClearSelection={() => setSelectedIds(new Set())}
        actions={bulkActions}
      />
    </PageContainer>
  )
}
