import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  checkSchedule,
  createScheduleEntry as createEntryApi,
  createSchedule as createScheduleApi,
  deleteScheduleEntry as deleteEntryApi,
  deleteSchedule as deleteScheduleApi,
  getSchedule,
  listSchedules,
  type ScheduleCheckResponse,
  type ScheduleCreate,
  type ScheduleDetail,
  type ScheduleEntryCreate,
  type ScheduleEntryList,
  type ScheduleEntryUpdate,
  type ScheduleList,
  type ScheduleUpdate,
  updateSchedule as updateScheduleApi,
} from "@/lib/generated/api"

export type Schedule = ScheduleDetail
export type ScheduleEntry = ScheduleEntryList
export type ScheduleCheckResult = ScheduleCheckResponse

export type { ScheduleCreate, ScheduleEntryCreate, ScheduleEntryUpdate, ScheduleUpdate }

// ---------------------------------------------------------------------------
// Schedule List
// ---------------------------------------------------------------------------

export interface UseSchedulesOptions {
  page?: number
  pageSize?: number
  search?: string
  orderBy?: string
  sortOrder?: "asc" | "desc"
  enabled?: boolean
}

export function useSchedules(pageOrOptions: number | UseSchedulesOptions = 1, pageSizeArg = 20) {
  const opts: UseSchedulesOptions = typeof pageOrOptions === "number" ? { page: pageOrOptions, pageSize: pageSizeArg } : pageOrOptions
  const { page = 1, pageSize = 20, search, orderBy, sortOrder, enabled } = opts

  return useQuery({
    queryKey: ["schedules", page, pageSize, search, orderBy, sortOrder],
    queryFn: async () => {
      const response = await listSchedules({
        query: {
          currentPage: page,
          pageSize,
          searchString: search,
          searchIgnoreCase: search ? true : undefined,
          orderBy,
          sortOrder,
        },
      })
      return response.data as { items: ScheduleList[]; total: number }
    },
    enabled,
  })
}

// ---------------------------------------------------------------------------
// Schedule Detail
// ---------------------------------------------------------------------------

export function useSchedule(scheduleId: string) {
  return useQuery({
    queryKey: ["schedule", scheduleId],
    queryFn: async () => {
      const response = await getSchedule({
        path: { schedule_id: scheduleId },
      })
      return response.data as ScheduleDetail
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
      const response = await checkSchedule({
        path: { schedule_id: scheduleId },
      })
      return response.data as ScheduleCheckResponse
    },
    enabled: !!scheduleId,
    refetchInterval: 60_000,
  })
}

// ---------------------------------------------------------------------------
// Schedule Mutations
// ---------------------------------------------------------------------------

export function useCreateSchedule() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: ScheduleCreate) => {
      const response = await createScheduleApi({ body: payload })
      return response.data as ScheduleDetail
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
      const response = await updateScheduleApi({
        path: { schedule_id: scheduleId },
        body: payload,
      })
      return response.data as ScheduleDetail
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
      await deleteScheduleApi({
        path: { schedule_id: scheduleId },
      })
    },
    onSuccess: (_data, scheduleId) => {
      queryClient.invalidateQueries({ queryKey: ["schedules"] })
      queryClient.invalidateQueries({ queryKey: ["schedule", scheduleId] })
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
      const response = await createEntryApi({
        path: { schedule_id: scheduleId },
        body: payload,
      })
      return response.data as ScheduleEntryList
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

export function useDeleteScheduleEntry(scheduleId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (entryId: string) => {
      await deleteEntryApi({
        path: { schedule_id: scheduleId, entry_id: entryId },
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
