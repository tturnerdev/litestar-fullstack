import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { client } from "@/lib/generated/api/client.gen"
import type { BackgroundTaskDetail, BackgroundTaskList } from "@/lib/generated/api/types.gen"

// ---------------------------------------------------------------------------
// Helpers (for endpoints not yet in generated SDK)
// ---------------------------------------------------------------------------

async function apiFetch<T>(url: string, options?: RequestInit): Promise<T> {
  const config = client.getConfig()
  const baseUrl = config.baseUrl ?? ""
  const token = typeof window !== "undefined" ? window.localStorage.getItem("access_token") : null
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }
  const response = await fetch(`${baseUrl}${url}`, {
    credentials: "include",
    ...options,
    headers: { ...headers, ...(options?.headers as Record<string, string>) },
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail ?? `Request failed (${response.status})`)
  }
  if (response.status === 204) return undefined as unknown as T
  return response.json()
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface PaginatedResponse<T> {
  items: T[]
  total: number
  limit?: number
  offset?: number
}

export interface UseTasksOptions {
  page?: number
  pageSize?: number
  taskType?: string
  status?: string
  entityType?: string
  entityId?: string
  orderBy?: string
  sortOrder?: "asc" | "desc"
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
  const { page = 1, pageSize = 20, taskType, status, entityType, entityId, orderBy, sortOrder } = options

  return useQuery({
    queryKey: taskKeys.list(options),
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set("currentPage", String(page))
      params.set("pageSize", String(pageSize))
      if (taskType) params.set("taskType", taskType)
      if (status) params.set("status", status)
      if (entityType) params.set("entityType", entityType)
      if (entityId) params.set("entityId", entityId)
      if (orderBy) params.set("orderBy", orderBy)
      if (sortOrder) params.set("sortOrder", sortOrder)
      return apiFetch<PaginatedResponse<BackgroundTaskList>>(`/api/tasks?${params.toString()}`)
    },
  })
}

// ---------------------------------------------------------------------------
// Task Detail
// ---------------------------------------------------------------------------

export function useTask(taskId: string) {
  return useQuery({
    queryKey: taskKeys.detail(taskId),
    queryFn: () => apiFetch<BackgroundTaskDetail>(`/api/tasks/${taskId}`),
    enabled: !!taskId,
    // Fallback polling when SSE is disconnected — primary updates come from
    // task.updated / task.completed / task.failed SSE events (see events.ts).
    refetchInterval: (query) => {
      const data = query.state.data
      if (data && (data.status === "pending" || data.status === "running")) {
        return 30_000
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
    queryFn: () => apiFetch<BackgroundTaskList[]>("/api/tasks/active"),
    // Fallback polling when SSE is disconnected — primary updates come from
    // task lifecycle SSE events (see events.ts).
    refetchInterval: 30_000,
  })
}

// ---------------------------------------------------------------------------
// Cancel Task
// ---------------------------------------------------------------------------

export function useCancelTask() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (taskId: string) =>
      apiFetch<BackgroundTaskDetail>(`/api/tasks/${taskId}/cancel`, {
        method: "POST",
      }),
    onSuccess: (_data, taskId) => {
      queryClient.invalidateQueries({ queryKey: taskKeys.all })
      queryClient.invalidateQueries({ queryKey: taskKeys.detail(taskId) })
      toast.success("Task cancelled")
    },
    onError: (error) => {
      toast.error("Unable to cancel task", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
