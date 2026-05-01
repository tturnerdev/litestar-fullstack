import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { client } from "@/lib/generated/api/client.gen"

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

export interface Schedule {
  id: string
  teamId: string
  name: string
  timezone: string
  isDefault: boolean
  scheduleType: "business_hours" | "holiday" | "custom"
  entries?: ScheduleEntry[]
  createdAt: string
  updatedAt: string
}

export interface ScheduleEntry {
  id: string
  scheduleId: string
  dayOfWeek: number | null // 0-6 (Mon-Sun), null for holidays
  startTime: string // "HH:MM"
  endTime: string // "HH:MM"
  date: string | null // ISO date for holidays
  label: string | null
  isClosed: boolean
}

export interface ScheduleCreate {
  name: string
  timezone: string
  scheduleType: "business_hours" | "holiday" | "custom"
  isDefault?: boolean
}

export interface ScheduleUpdate {
  name?: string
  timezone?: string
  scheduleType?: "business_hours" | "holiday" | "custom"
  isDefault?: boolean
}

export interface ScheduleEntryCreate {
  dayOfWeek?: number | null
  startTime: string
  endTime: string
  date?: string | null
  label?: string | null
  isClosed?: boolean
}

export interface ScheduleEntryUpdate {
  dayOfWeek?: number | null
  startTime?: string
  endTime?: string
  date?: string | null
  label?: string | null
  isClosed?: boolean
}

export interface ScheduleCheckResult {
  isOpen: boolean
  currentEntry: ScheduleEntry | null
}

// ---------------------------------------------------------------------------
// Schedule List
// ---------------------------------------------------------------------------

export interface UseSchedulesOptions {
  page?: number
  pageSize?: number
  search?: string
  orderBy?: string
  sortOrder?: "asc" | "desc"
}

export function useSchedules(pageOrOptions: number | UseSchedulesOptions = 1, pageSizeArg = 20) {
  const opts: UseSchedulesOptions =
    typeof pageOrOptions === "number" ? { page: pageOrOptions, pageSize: pageSizeArg } : pageOrOptions
  const { page = 1, pageSize = 20, search, orderBy, sortOrder } = opts

  return useQuery({
    queryKey: ["schedules", page, pageSize, search, orderBy, sortOrder],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set("currentPage", String(page))
      params.set("pageSize", String(pageSize))
      if (search) {
        params.set("searchString", search)
        params.set("searchIgnoreCase", "true")
      }
      if (orderBy) params.set("orderBy", orderBy)
      if (sortOrder) params.set("sortOrder", sortOrder)
      return apiFetch<{ items: Schedule[]; total: number }>(`/api/schedules?${params.toString()}`)
    },
  })
}

// ---------------------------------------------------------------------------
// Schedule Detail
// ---------------------------------------------------------------------------

export function useSchedule(scheduleId: string) {
  return useQuery({
    queryKey: ["schedule", scheduleId],
    queryFn: async () => {
      return apiFetch<Schedule>(`/api/schedules/${scheduleId}`)
    },
    enabled: !!scheduleId,
  })
}

// ---------------------------------------------------------------------------
// Schedule Check (open/closed status)
// ---------------------------------------------------------------------------

export function useCheckSchedule(scheduleId: string) {
  return useQuery({
    queryKey: ["schedule", scheduleId, "check"],
    queryFn: async () => {
      return apiFetch<ScheduleCheckResult>(`/api/schedules/${scheduleId}/check`)
    },
    enabled: !!scheduleId,
    refetchInterval: 60_000, // re-check every minute
  })
}

// ---------------------------------------------------------------------------
// Schedule Mutations
// ---------------------------------------------------------------------------

export function useCreateSchedule() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: ScheduleCreate) => {
      return apiFetch<Schedule>("/api/schedules", {
        method: "POST",
        body: JSON.stringify(payload),
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["schedules"] })
      toast.success("Schedule created")
    },
    onError: (error) => {
      toast.error("Unable to create schedule", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUpdateSchedule(scheduleId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: ScheduleUpdate) => {
      return apiFetch<Schedule>(`/api/schedules/${scheduleId}`, {
        method: "PUT",
        body: JSON.stringify(payload),
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["schedules"] })
      queryClient.invalidateQueries({ queryKey: ["schedule", scheduleId] })
      toast.success("Schedule updated")
    },
    onError: (error) => {
      toast.error("Unable to update schedule", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteSchedule() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (scheduleId: string) => {
      return apiFetch<void>(`/api/schedules/${scheduleId}`, {
        method: "DELETE",
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["schedules"] })
      toast.success("Schedule deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete schedule", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Schedule Entry Mutations
// ---------------------------------------------------------------------------

export function useCreateScheduleEntry(scheduleId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: ScheduleEntryCreate) => {
      return apiFetch<ScheduleEntry>(`/api/schedules/${scheduleId}/entries`, {
        method: "POST",
        body: JSON.stringify(payload),
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["schedule", scheduleId] })
      queryClient.invalidateQueries({ queryKey: ["schedule", scheduleId, "check"] })
      toast.success("Entry added")
    },
    onError: (error) => {
      toast.error("Unable to add entry", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUpdateScheduleEntry(scheduleId: string, entryId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: ScheduleEntryUpdate) => {
      return apiFetch<ScheduleEntry>(`/api/schedules/${scheduleId}/entries/${entryId}`, {
        method: "PUT",
        body: JSON.stringify(payload),
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["schedule", scheduleId] })
      queryClient.invalidateQueries({ queryKey: ["schedule", scheduleId, "check"] })
      toast.success("Entry updated")
    },
    onError: (error) => {
      toast.error("Unable to update entry", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteScheduleEntry(scheduleId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (entryId: string) => {
      return apiFetch<void>(`/api/schedules/${scheduleId}/entries/${entryId}`, {
        method: "DELETE",
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["schedule", scheduleId] })
      queryClient.invalidateQueries({ queryKey: ["schedule", scheduleId, "check"] })
      toast.success("Entry removed")
    },
    onError: (error) => {
      toast.error("Unable to remove entry", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
