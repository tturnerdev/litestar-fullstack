import { useState } from "react"
import { Link } from "@tanstack/react-router"
import { Activity, Loader2 } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { TaskStatusBadge } from "@/components/tasks/task-status-badge"
import { useActiveTasks } from "@/lib/api/hooks/tasks"
import { cn } from "@/lib/utils"

function formatTaskType(taskType: string): string {
  return taskType
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

export function ActiveTaskIndicator() {
  const [open, setOpen] = useState(false)
  const { data: activeTasks } = useActiveTasks()

  const count = activeTasks?.length ?? 0
  if (count === 0) return null

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="relative h-8 gap-1.5 px-2"
          aria-label={`${count} active task${count === 1 ? "" : "s"}`}
        >
          <Loader2 className="h-4 w-4 animate-spin text-blue-500" />
          <Badge
            variant="secondary"
            className="h-5 min-w-5 justify-center px-1 text-[10px] font-semibold"
          >
            {count}
          </Badge>
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 p-0">
        <div className="border-b px-4 py-3">
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-muted-foreground" />
            <h4 className="text-sm font-semibold">Active Tasks</h4>
          </div>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {count} task{count === 1 ? "" : "s"} in progress
          </p>
        </div>
        <div className="max-h-72 overflow-y-auto">
          {(activeTasks ?? []).map((task) => (
            <Link
              key={task.id}
              to="/tasks/$taskId"
              params={{ taskId: task.id }}
              className={cn(
                "flex items-center justify-between gap-3 border-b px-4 py-3 transition-colors",
                "hover:bg-muted/50 last:border-b-0",
              )}
              onClick={() => setOpen(false)}
            >
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">
                  {formatTaskType(task.taskType)}
                </p>
                {task.progress != null && task.progress > 0 && (
                  <div className="mt-1.5 flex items-center gap-2">
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full rounded-full bg-blue-500 transition-all duration-300"
                        style={{ width: `${Math.min(task.progress, 100)}%` }}
                      />
                    </div>
                    <span className="text-[10px] font-medium text-muted-foreground">
                      {Math.round(task.progress)}%
                    </span>
                  </div>
                )}
              </div>
              <TaskStatusBadge status={task.status} />
            </Link>
          ))}
        </div>
        <div className="border-t px-4 py-2">
          <Link
            to="/tasks"
            className="text-xs font-medium text-primary hover:underline"
            onClick={() => setOpen(false)}
          >
            View all tasks
          </Link>
        </div>
      </PopoverContent>
    </Popover>
  )
}
