import { createFileRoute, Link } from "@tanstack/react-router"
import {
  AlertCircle,
  ArrowLeft,
  Calendar,
  ChevronDown,
  ChevronRight,
  Clock,
  Copy,
  FileJson,
  Hash,
  Layers,
  Loader2,
  MoreHorizontal,
  RotateCcw,
  Trash2,
  User,
  XCircle,
} from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"
import { TaskStatusBadge } from "@/components/tasks/task-status-badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
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
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { CopyButton } from "@/components/ui/copy-button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useCancelTask, useRetryTask, useTask } from "@/lib/api/hooks/tasks"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"

export const Route = createFileRoute("/_app/tasks/$taskId/")({
  component: TaskDetailPage,
})

// -- Helpers ------------------------------------------------------------------

function formatTaskType(taskType: string): string {
  return taskType.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())
}

function formatEntityType(entityType: string | null | undefined): string {
  if (!entityType) return "--"
  return entityType.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())
}

// -- Timestamp field ----------------------------------------------------------

function TimestampField({ label, icon: Icon, value }: { label: string; icon: React.ComponentType<{ className?: string }>; value: string | null | undefined }) {
  return (
    <div className="flex items-start gap-2.5">
      <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
        <Icon className="h-3.5 w-3.5 text-muted-foreground" />
      </div>
      <div className="min-w-0">
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
        {value ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <p className="mt-0.5 cursor-default text-sm">{formatRelativeTimeShort(value)}</p>
            </TooltipTrigger>
            <TooltipContent>{formatDateTime(value)}</TooltipContent>
          </Tooltip>
        ) : (
          <p className="mt-0.5 text-sm text-muted-foreground/70">--</p>
        )}
      </div>
    </div>
  )
}

// -- JSON Viewer section ------------------------------------------------------

function JsonSection({ title, data, defaultOpen }: { title: string; data: Record<string, unknown> | null | undefined; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen ?? false)

  if (!data || Object.keys(data).length === 0) return null

  const formatted = JSON.stringify(data, null, 2)

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <Card className="border-border/60 bg-card/80">
        <CollapsibleTrigger asChild>
          <CardHeader className="cursor-pointer select-none pb-2 hover:bg-muted/30 transition-colors rounded-t-xl">
            <CardTitle className="flex items-center gap-2 text-base">
              {open ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
              <FileJson className="h-4 w-4 text-muted-foreground" />
              {title}
            </CardTitle>
          </CardHeader>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <CardContent className="pt-0">
            <div className="relative">
              <div className="absolute right-2 top-2">
                <CopyButton value={formatted} label={title} />
              </div>
              <pre className="overflow-x-auto rounded-md bg-muted/50 p-4 text-xs font-mono leading-relaxed">{formatted}</pre>
            </div>
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  )
}

// -- Loading Skeleton ---------------------------------------------------------

function TaskDetailSkeleton() {
  return (
    <PageContainer className="flex-1 space-y-6">
      <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="space-y-3">
          <Skeleton className="h-3 w-48" />
          <Skeleton className="h-9 w-80" />
          <Skeleton className="h-4 w-56" />
        </div>
        <div className="flex items-center gap-2">
          <Skeleton className="h-9 w-24" />
          <Skeleton className="h-9 w-20" />
        </div>
      </div>
      <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
        <div className="space-y-4">
          <Card className="border-border/60">
            <CardContent className="space-y-4 py-6">
              <Skeleton className="h-6 w-1/3" />
              <Skeleton className="h-40 w-full rounded-md" />
            </CardContent>
          </Card>
        </div>
        <div className="space-y-4">
          <Card className="border-border/60">
            <CardContent className="space-y-4 py-4">
              {Array.from({ length: 6 }).map((_, i) => (
                // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
                <div key={`skel-${i}`} className="space-y-1.5">
                  <Skeleton className="h-3 w-16" />
                  <Skeleton className="h-5 w-24" />
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </PageContainer>
  )
}

// -- Error State --------------------------------------------------------------

function TaskNotFound({ message }: { message: string }) {
  return (
    <PageContainer className="flex-1">
      <div className="flex flex-col items-center justify-center py-24">
        <div className="flex h-16 w-16 items-center justify-center rounded-full bg-muted/50">
          <AlertCircle className="h-8 w-8 text-muted-foreground" />
        </div>
        <h2 className="mt-4 text-lg font-semibold">Unable to load task</h2>
        <p className="mt-1 max-w-sm text-center text-sm text-muted-foreground">{message}</p>
        <Button variant="outline" size="sm" asChild className="mt-6">
          <Link to="/tasks">
            <ArrowLeft className="mr-2 h-4 w-4" /> Back to Tasks
          </Link>
        </Button>
      </div>
    </PageContainer>
  )
}

// -- Main Page ----------------------------------------------------------------

function TaskDetailPage() {
  const { taskId } = Route.useParams()
  const { data: task, isLoading, isError } = useTask(taskId)
  const cancelMutation = useCancelTask()
  const retryMutation = useRetryTask()
  const [showCancelDialog, setShowCancelDialog] = useState(false)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)

  useDocumentTitle(task ? `${formatTaskType(task.taskType)} - Task` : "Task Details")

  if (isLoading) {
    return <TaskDetailSkeleton />
  }

  if (isError) {
    return <TaskNotFound message="We couldn't load this task. It may have been deleted or you may not have permission to view it." />
  }

  if (!task) {
    return <TaskNotFound message="This task could not be found. It may have been deleted." />
  }

  const isActive = task.status === "pending" || task.status === "running"
  const isRetryable = task.status === "failed" || task.status === "aborted"

  return (
    <PageContainer className="flex-1 space-y-6">
      <PageHeader
        eyebrow="System"
        title={formatTaskType(task.taskType)}
        description={`Task ${task.id.slice(0, 8)}... · Created ${formatDateTime(task.createdAt ?? "")}`}
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/">Home</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/tasks">Tasks</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>{formatTaskType(task.taskType)}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-2">
            {isRetryable && (
              <Button
                size="sm"
                variant="outline"
                onClick={() =>
                  retryMutation.mutate(taskId, {
                    onSuccess: () => toast.success("Task retry initiated successfully"),
                  })
                }
                disabled={retryMutation.isPending}
              >
                {retryMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RotateCcw className="mr-2 h-4 w-4" />}
                Retry
              </Button>
            )}
            {isActive && (
              <Button
                size="sm"
                variant="outline"
                className="text-destructive hover:bg-destructive/10"
                onClick={() => setShowCancelDialog(true)}
                disabled={cancelMutation.isPending}
              >
                {cancelMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <XCircle className="mr-2 h-4 w-4" />}
                Cancel Task
              </Button>
            )}
            <Button variant="outline" size="sm" asChild>
              <Link to="/tasks">
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
                <DropdownMenuItem onClick={() => navigator.clipboard.writeText(taskId)}>
                  <Copy className="mr-2 h-4 w-4" />
                  Copy Task ID
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem className="text-destructive focus:text-destructive" onClick={() => setShowDeleteDialog(true)}>
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete Task
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        }
      />

      {/* Two-column layout: details + sidebar */}
      <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
        {/* Main column */}
        <div className="min-w-0 space-y-6">
          {/* Progress section */}
          {task.progress != null && task.progress > 0 && (
            <PageSection delay={0.05}>
              <SectionErrorBoundary name="Task Progress">
                <Card className="border-border/60 bg-card/80">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Progress</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-muted-foreground">{task.status === "completed" ? "Complete" : task.status === "failed" ? "Failed" : "In progress..."}</span>
                        <span className="font-medium">{Math.round(task.progress)}%</span>
                      </div>
                      <div className="h-2.5 overflow-hidden rounded-full bg-muted">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${
                            task.status === "failed" ? "bg-red-500" : task.status === "completed" ? "bg-green-500" : "bg-blue-500"
                          }`}
                          style={{ width: `${Math.min(task.progress, 100)}%` }}
                        />
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </SectionErrorBoundary>
            </PageSection>
          )}

          {/* Error section */}
          {task.status === "failed" && task.errorMessage && (
            <PageSection delay={0.1}>
              <SectionErrorBoundary name="Task Error">
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertTitle>Task Failed</AlertTitle>
                  <AlertDescription>{task.errorMessage}</AlertDescription>
                </Alert>
              </SectionErrorBoundary>
            </PageSection>
          )}

          {/* Payload section */}
          <PageSection delay={0.15}>
            <SectionErrorBoundary name="Task Payload">
              <JsonSection title="Payload" data={task.payload} defaultOpen={!task.result} />
            </SectionErrorBoundary>
          </PageSection>

          {/* Result section */}
          {task.result && (
            <PageSection delay={0.2}>
              <SectionErrorBoundary name="Task Result">
                <JsonSection title="Result" data={task.result} defaultOpen />
              </SectionErrorBoundary>
            </PageSection>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          <PageSection delay={0.1}>
            <SectionErrorBoundary name="Task Details">
              <Card className="border-border/60 bg-card/80">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Details</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Status */}
                  <div className="space-y-1">
                    <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Status</p>
                    <TaskStatusBadge status={task.status} />
                  </div>

                  {/* Task Type */}
                  <div className="flex items-start gap-2.5">
                    <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
                      <Layers className="h-3.5 w-3.5 text-muted-foreground" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Task Type</p>
                      <p className="mt-0.5 text-sm">{formatTaskType(task.taskType)}</p>
                    </div>
                  </div>

                  {/* Entity */}
                  {task.entityType && (
                    <div className="flex items-start gap-2.5">
                      <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
                        <Hash className="h-3.5 w-3.5 text-muted-foreground" />
                      </div>
                      <div className="min-w-0">
                        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Entity</p>
                        <p className="mt-0.5 text-sm">{formatEntityType(task.entityType)}</p>
                        {task.entityId && <p className="mt-0.5 font-mono text-xs text-muted-foreground">{task.entityId}</p>}
                      </div>
                    </div>
                  )}

                  {/* Initiated By */}
                  {task.initiatedByName && (
                    <div className="flex items-start gap-2.5">
                      <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
                        <User className="h-3.5 w-3.5 text-muted-foreground" />
                      </div>
                      <div className="min-w-0">
                        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Initiated By</p>
                        <p className="mt-0.5 text-sm">{task.initiatedByName}</p>
                      </div>
                    </div>
                  )}

                  {/* SAQ Job Key */}
                  {task.saqJobKey && (
                    <div className="flex items-start gap-2.5">
                      <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
                        <Hash className="h-3.5 w-3.5 text-muted-foreground" />
                      </div>
                      <div className="min-w-0">
                        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Job Key</p>
                        <div className="mt-0.5 flex items-center gap-1">
                          <p className="font-mono text-xs text-muted-foreground truncate">{task.saqJobKey}</p>
                          <CopyButton value={task.saqJobKey} label="job key" />
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Timestamps */}
                  <div className="border-t border-border/40 pt-4 space-y-3">
                    <TimestampField label="Created" icon={Calendar} value={task.createdAt} />
                    <TimestampField label="Started" icon={Clock} value={task.startedAt} />
                    <TimestampField label="Completed" icon={Clock} value={task.completedAt} />
                    <TimestampField label="Updated" icon={Calendar} value={task.updatedAt} />
                  </div>

                  {/* Task ID */}
                  <div className="border-t border-border/40 pt-4">
                    <div className="flex items-center gap-1">
                      <p className="font-mono text-[10px] text-muted-foreground/60 truncate">{task.id}</p>
                      <CopyButton value={task.id} label="task ID" />
                    </div>
                  </div>
                </CardContent>
              </Card>
            </SectionErrorBoundary>
          </PageSection>
        </div>
      </div>

      {/* Cancel confirmation dialog */}
      <AlertDialog open={showCancelDialog} onOpenChange={setShowCancelDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Cancel this task?</AlertDialogTitle>
            <AlertDialogDescription>
              This will attempt to cancel the running task. Depending on its current state, some work may have already been completed and cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Keep Running</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() =>
                cancelMutation.mutate(taskId, {
                  onSuccess: () => toast.success("Task cancelled successfully"),
                })
              }
              disabled={cancelMutation.isPending}
            >
              {cancelMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Cancel Task
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete confirmation dialog */}
      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete this task?</AlertDialogTitle>
            <AlertDialogDescription>This will permanently delete this task record. This action cannot be undone.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => {
                toast.info("Task deletion is not yet implemented")
                setShowDeleteDialog(false)
              }}
            >
              Delete Task
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </PageContainer>
  )
}
