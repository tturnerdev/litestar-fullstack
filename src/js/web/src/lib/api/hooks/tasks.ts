import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  type BackgroundTaskDetail,
  type BackgroundTaskList,
  cancelTask as cancelTaskApi,
  deleteTask as deleteTaskApi,
  getTask,
  listActiveTasks,
  listTasks,
} from "@/lib/generated/api"
import { sseStatus } from "./events"

export type { BackgroundTaskDetail, BackgroundTaskList }

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface UseTasksOptions {
  page?: number
  pageSize?: number
  taskType?: string
  status?: string
  entityType?: string
  entityId?: string
  orderBy?: string
  sortOrder?: "asc" | "desc"
  /** When set, the query will automatically refetch on this interval (ms). */
  refetchInterval?: number | false
}

// ---------------------------------------------------------------------------
// Polling constants
// ---------------------------------------------------------------------------

/** Normal polling interval when SSE is delivering real-time updates. */
const POLL_INTERVAL_NORMAL = 30_000

/** Faster polling interval after SSE has been disconnected long enough. */
const POLL_INTERVAL_FAST = 5_000

/** How long SSE must be down before we switch to fast polling (ms). */
const SSE_DISCONNECT_THRESHOLD = 60_000

function getPollingInterval(): number {
  if (sseStatus.connected) return POLL_INTERVAL_NORMAL
  if (sseStatus.disconnectedSince != null && Date.now() - sseStatus.disconnectedSince > SSE_DISCONNECT_THRESHOLD) {
    return POLL_INTERVAL_FAST
  }
  return POLL_INTERVAL_NORMAL
}

// ---------------------------------------------------------------------------
// Query key factory
// ---------------------------------------------------------------------------

export const taskKeys = {
  all: ["tasks"] as const,
  lists: () => [...taskKeys.all, "list"] as const,
  list: (filters: UseTasksOptions) => [...taskKeys.lists(), filters] as const,
  details: () => [...taskKeys.all, "detail"] as const,
  detail: (id: string) => [...taskKeys.details(), id] as const,
  active: () => [...taskKeys.all, "active"] as const,
}

// ---------------------------------------------------------------------------
// Task List (paginated)
// ---------------------------------------------------------------------------

export function useTasks(options: UseTasksOptions = {}) {
  const { page = 1, pageSize = 20, taskType, status, entityType, entityId, orderBy, sortOrder, refetchInterval } = options

  return useQuery({
    queryKey: taskKeys.list(options),
    queryFn: async () => {
      const response = await listTasks({
        query: {
          currentPage: page,
          pageSize,
          taskType,
          status,
          entityType,
          entityId,
          orderBy,
          sortOrder,
        },
      })
      return response.data as { items: BackgroundTaskList[]; total: number }
    },
    ...(refetchInterval !== undefined ? { refetchInterval } : {}),
  })
}

// ---------------------------------------------------------------------------
// Task Detail
// ---------------------------------------------------------------------------

export function useTask(taskId: string) {
  return useQuery({
    queryKey: taskKeys.detail(taskId),
    queryFn: async () => {
      const response = await getTask({
        path: { task_id: taskId },
      })
      return response.data as BackgroundTaskDetail
    },
    enabled: !!taskId,
    refetchInterval: (query) => {
      const data = query.state.data
      if (data && (data.status === "pending" || data.status === "running")) {
        return getPollingInterval()
      }
      return false
    },
  })
}

// ---------------------------------------------------------------------------
// Active Tasks (current user)
// ---------------------------------------------------------------------------

export function useActiveTasks() {
  return useQuery({
    queryKey: taskKeys.active(),
    queryFn: async () => {
      const response = await listActiveTasks()
      return response.data as BackgroundTaskList[]
    },
    refetchInterval: () => getPollingInterval(),
  })
}

// ---------------------------------------------------------------------------
// Retry Task
// ---------------------------------------------------------------------------

export function useRetryTask() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (taskId: string) => {
      void taskId
      throw new Error("NOT_IMPLEMENTED")
    },
    onSuccess: (_data, taskId) => {
      queryClient.invalidateQueries({ queryKey: taskKeys.all })
      queryClient.invalidateQueries({ queryKey: taskKeys.detail(taskId) })
    },
  })
}

// ---------------------------------------------------------------------------
// Cancel Task
// ---------------------------------------------------------------------------

export function useCancelTask() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (taskId: string) => {
      const response = await cancelTaskApi({
        path: { task_id: taskId },
      })
      return response.data as BackgroundTaskDetail
    },
    onSuccess: (_data, taskId) => {
      queryClient.invalidateQueries({ queryKey: taskKeys.all })
      queryClient.invalidateQueries({ queryKey: taskKeys.detail(taskId) })
    },
  })
}

// ---------------------------------------------------------------------------
// Delete Task
// ---------------------------------------------------------------------------

export function useDeleteTask() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (taskId: string) => {
      const response = await deleteTaskApi({
        path: { task_id: taskId },
      })
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: taskKeys.all })
    },
  })
}
