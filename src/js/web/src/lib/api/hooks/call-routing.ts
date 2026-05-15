import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import type {
  CallQueueCreate,
  CallQueueMemberCreate,
  CallQueueUpdate,
  IvrMenuCreate,
  IvrMenuOptionCreate,
  IvrMenuUpdate,
  RingGroupCreate,
  RingGroupMemberCreate,
  RingGroupUpdate,
  TimeConditionCreate,
  TimeConditionUpdate,
} from "@/lib/generated/api"
import {
  createCallQueue,
  createCallQueueMember,
  createIvrMenu,
  createIvrMenuOption,
  createRingGroup,
  createRingGroupMember,
  createTimeCondition,
  deleteCallQueue,
  deleteCallQueueMember,
  deleteIvrMenu,
  deleteIvrMenuOption,
  deleteRingGroup,
  deleteRingGroupMember,
  deleteTimeCondition,
  getCallQueue,
  getIvrMenu,
  getRingGroup,
  getTimeCondition,
  listCallQueues,
  listIvrMenus,
  listRingGroups,
  listTimeConditions,
  pauseCallQueueMember,
  setTimeConditionOverride,
  updateCallQueue,
  updateCallQueueMember,
  updateIvrMenu,
  updateIvrMenuOption,
  updateRingGroup,
  updateRingGroupMember,
  updateTimeCondition,
} from "@/lib/generated/api"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function unwrap<T>(result: { data?: T; error?: unknown }): T {
  if (result.error) {
    const err = result.error as { detail?: string; message?: string } | null
    throw new Error(err?.detail ?? err?.message ?? "Request failed")
  }
  return result.data as T
}

// ---------------------------------------------------------------------------
// Re-exports — generated types
// ---------------------------------------------------------------------------

export type {
  CallQueue,
  CallQueueCreate,
  CallQueueMember,
  CallQueueMemberCreate,
  CallQueueUpdate,
  IvrMenu,
  IvrMenuCreate,
  IvrMenuOption,
  IvrMenuOptionCreate,
  IvrMenuOptionUpdate,
  IvrMenuUpdate,
  RingGroup,
  RingGroupCreate,
  RingGroupMember,
  RingGroupMemberCreate,
  RingGroupUpdate,
  TimeCondition,
  TimeConditionCreate,
  TimeConditionUpdate,
} from "@/lib/generated/api"

// ---------------------------------------------------------------------------
// Common
// ---------------------------------------------------------------------------

export interface UseListOptions {
  page?: number
  pageSize?: number
  search?: string
  orderBy?: string
  sortOrder?: "asc" | "desc"
  enabled?: boolean
}

// ===========================================================================
// Time Conditions
// ===========================================================================

export function useTimeConditions(opts: UseListOptions = {}) {
  return useQuery({
    queryKey: ["call-routing", "time-conditions", opts.page, opts.pageSize, opts.search, opts.orderBy, opts.sortOrder],
    queryFn: () =>
      listTimeConditions({
        query: {
          currentPage: opts.page ?? 1,
          pageSize: opts.pageSize ?? 25,
          searchString: opts.search,
          orderBy: opts.orderBy,
          sortOrder: opts.sortOrder,
        },
      }).then(unwrap),
    enabled: opts.enabled,
  })
}

export function useTimeCondition(id: string) {
  return useQuery({
    queryKey: ["call-routing", "time-condition", id],
    queryFn: () => getTimeCondition({ path: { time_condition_id: id } }).then(unwrap),
    enabled: !!id,
  })
}

export function useCreateTimeCondition() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: TimeConditionCreate) => createTimeCondition({ body: payload }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "time-conditions"] })
      toast.success("Time condition created")
    },
    onError: (error) => {
      toast.error("Unable to create time condition", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUpdateTimeCondition(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: TimeConditionUpdate) => updateTimeCondition({ path: { time_condition_id: id }, body: payload }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "time-conditions"] })
      queryClient.invalidateQueries({ queryKey: ["call-routing", "time-condition", id] })
      toast.success("Time condition updated")
    },
    onError: (error) => {
      toast.error("Unable to update time condition", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteTimeCondition() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => deleteTimeCondition({ path: { time_condition_id: id } }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "time-conditions"] })
      toast.success("Time condition deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete time condition", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useSetTimeConditionOverride(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (overrideMode: string) =>
      setTimeConditionOverride({
        path: { time_condition_id: id },
        body: { overrideMode },
      }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "time-condition", id] })
      queryClient.invalidateQueries({ queryKey: ["call-routing", "time-conditions"] })
      toast.success("Override mode updated")
    },
    onError: (error) => {
      toast.error("Unable to update override mode", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ===========================================================================
// IVR Menus
// ===========================================================================

export function useIvrMenus(opts: UseListOptions = {}) {
  return useQuery({
    queryKey: ["call-routing", "ivr-menus", opts.page, opts.pageSize, opts.search, opts.orderBy, opts.sortOrder],
    queryFn: () =>
      listIvrMenus({
        query: {
          currentPage: opts.page ?? 1,
          pageSize: opts.pageSize ?? 25,
          searchString: opts.search,
          orderBy: opts.orderBy,
          sortOrder: opts.sortOrder,
        },
      }).then(unwrap),
    enabled: opts.enabled,
  })
}

export function useIvrMenu(id: string) {
  return useQuery({
    queryKey: ["call-routing", "ivr-menu", id],
    queryFn: () => getIvrMenu({ path: { ivr_menu_id: id } }).then(unwrap),
    enabled: !!id,
  })
}

export function useCreateIvrMenu() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: IvrMenuCreate) => createIvrMenu({ body: payload }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "ivr-menus"] })
      toast.success("IVR menu created")
    },
    onError: (error) => {
      toast.error("Unable to create IVR menu", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUpdateIvrMenu(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: IvrMenuUpdate) => updateIvrMenu({ path: { ivr_menu_id: id }, body: payload }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "ivr-menus"] })
      queryClient.invalidateQueries({ queryKey: ["call-routing", "ivr-menu", id] })
      toast.success("IVR menu updated")
    },
    onError: (error) => {
      toast.error("Unable to update IVR menu", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteIvrMenu() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => deleteIvrMenu({ path: { ivr_menu_id: id } }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "ivr-menus"] })
      toast.success("IVR menu deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete IVR menu", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// IVR Menu Options

export function useCreateIvrMenuOption(menuId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: IvrMenuOptionCreate) => createIvrMenuOption({ path: { ivr_menu_id: menuId }, body: payload }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "ivr-menu", menuId] })
      toast.success("Option added")
    },
    onError: (error) => {
      toast.error("Unable to add option", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteIvrMenuOption(menuId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (optionId: string) => deleteIvrMenuOption({ path: { ivr_menu_id: menuId, option_id: optionId } }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "ivr-menu", menuId] })
      toast.success("Option removed")
    },
    onError: (error) => {
      toast.error("Unable to remove option", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useReorderIvrMenuOptions(menuId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ optionA, optionB }: { optionA: { id: string; sortOrder: number }; optionB: { id: string; sortOrder: number } }) => {
      await Promise.all([
        updateIvrMenuOption({
          path: { ivr_menu_id: menuId, option_id: optionA.id },
          body: { sortOrder: optionB.sortOrder },
        }),
        updateIvrMenuOption({
          path: { ivr_menu_id: menuId, option_id: optionB.id },
          body: { sortOrder: optionA.sortOrder },
        }),
      ])
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "ivr-menu", menuId] })
      toast.success("Options reordered")
    },
    onError: (error) => {
      toast.error("Unable to reorder options", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ===========================================================================
// Call Queues
// ===========================================================================

export function useCallQueues(opts: UseListOptions = {}) {
  return useQuery({
    queryKey: ["call-routing", "call-queues", opts.page, opts.pageSize, opts.search, opts.orderBy, opts.sortOrder],
    queryFn: () =>
      listCallQueues({
        query: {
          currentPage: opts.page ?? 1,
          pageSize: opts.pageSize ?? 25,
          searchString: opts.search,
          orderBy: opts.orderBy,
          sortOrder: opts.sortOrder,
        },
      }).then(unwrap),
    enabled: opts.enabled,
  })
}

export function useCallQueue(id: string) {
  return useQuery({
    queryKey: ["call-routing", "call-queue", id],
    queryFn: () => getCallQueue({ path: { call_queue_id: id } }).then(unwrap),
    enabled: !!id,
  })
}

export function useCreateCallQueue() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: CallQueueCreate) => createCallQueue({ body: payload }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "call-queues"] })
      toast.success("Call queue created")
    },
    onError: (error) => {
      toast.error("Unable to create call queue", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUpdateCallQueue(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: CallQueueUpdate) => updateCallQueue({ path: { call_queue_id: id }, body: payload }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "call-queues"] })
      queryClient.invalidateQueries({ queryKey: ["call-routing", "call-queue", id] })
      toast.success("Call queue updated")
    },
    onError: (error) => {
      toast.error("Unable to update call queue", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteCallQueue() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => deleteCallQueue({ path: { call_queue_id: id } }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "call-queues"] })
      toast.success("Call queue deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete call queue", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// Call Queue Members

export function useCreateCallQueueMember(queueId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: CallQueueMemberCreate) => createCallQueueMember({ path: { call_queue_id: queueId }, body: payload }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "call-queue", queueId] })
      toast.success("Member added")
    },
    onError: (error) => {
      toast.error("Unable to add member", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteCallQueueMember(queueId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (memberId: string) => deleteCallQueueMember({ path: { call_queue_id: queueId, member_id: memberId } }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "call-queue", queueId] })
      toast.success("Member removed")
    },
    onError: (error) => {
      toast.error("Unable to remove member", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function usePauseCallQueueMember(queueId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ memberId, isPaused }: { memberId: string; isPaused: boolean }) =>
      pauseCallQueueMember({
        path: { call_queue_id: queueId, member_id: memberId },
        body: { isPaused },
      }).then(unwrap),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "call-queue", queueId] })
      toast.success(variables.isPaused ? "Member paused" : "Member unpaused")
    },
    onError: (error) => {
      toast.error("Unable to update member", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useReorderCallQueueMembers(queueId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ memberA, memberB }: { memberA: { id: string; priority: number }; memberB: { id: string; priority: number } }) => {
      await Promise.all([
        updateCallQueueMember({
          path: { call_queue_id: queueId, member_id: memberA.id },
          body: { priority: memberB.priority },
        }),
        updateCallQueueMember({
          path: { call_queue_id: queueId, member_id: memberB.id },
          body: { priority: memberA.priority },
        }),
      ])
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "call-queue", queueId] })
      toast.success("Members reordered")
    },
    onError: (error) => {
      toast.error("Unable to reorder members", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ===========================================================================
// Ring Groups
// ===========================================================================

export function useRingGroups(opts: UseListOptions = {}) {
  return useQuery({
    queryKey: ["call-routing", "ring-groups", opts.page, opts.pageSize, opts.search, opts.orderBy, opts.sortOrder],
    queryFn: () =>
      listRingGroups({
        query: {
          currentPage: opts.page ?? 1,
          pageSize: opts.pageSize ?? 25,
          searchString: opts.search,
          orderBy: opts.orderBy,
          sortOrder: opts.sortOrder,
        },
      }).then(unwrap),
    enabled: opts.enabled,
  })
}

export function useRingGroup(id: string) {
  return useQuery({
    queryKey: ["call-routing", "ring-group", id],
    queryFn: () => getRingGroup({ path: { ring_group_id: id } }).then(unwrap),
    enabled: !!id,
  })
}

export function useCreateRingGroup() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: RingGroupCreate) => createRingGroup({ body: payload }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "ring-groups"] })
      toast.success("Ring group created")
    },
    onError: (error) => {
      toast.error("Unable to create ring group", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUpdateRingGroup(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: RingGroupUpdate) => updateRingGroup({ path: { ring_group_id: id }, body: payload }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "ring-groups"] })
      queryClient.invalidateQueries({ queryKey: ["call-routing", "ring-group", id] })
      toast.success("Ring group updated")
    },
    onError: (error) => {
      toast.error("Unable to update ring group", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteRingGroup() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => deleteRingGroup({ path: { ring_group_id: id } }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "ring-groups"] })
      toast.success("Ring group deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete ring group", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// Ring Group Members

export function useCreateRingGroupMember(groupId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: RingGroupMemberCreate) => createRingGroupMember({ path: { ring_group_id: groupId }, body: payload }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "ring-group", groupId] })
      toast.success("Member added")
    },
    onError: (error) => {
      toast.error("Unable to add member", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteRingGroupMember(groupId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (memberId: string) => deleteRingGroupMember({ path: { ring_group_id: groupId, member_id: memberId } }).then(unwrap),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "ring-group", groupId] })
      toast.success("Member removed")
    },
    onError: (error) => {
      toast.error("Unable to remove member", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useReorderRingGroupMembers(groupId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ memberA, memberB }: { memberA: { id: string; sortOrder: number }; memberB: { id: string; sortOrder: number } }) => {
      await Promise.all([
        updateRingGroupMember({
          path: { ring_group_id: groupId, member_id: memberA.id },
          body: { sortOrder: memberB.sortOrder },
        }),
        updateRingGroupMember({
          path: { ring_group_id: groupId, member_id: memberB.id },
          body: { sortOrder: memberA.sortOrder },
        }),
      ])
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "ring-group", groupId] })
      toast.success("Members reordered")
    },
    onError: (error) => {
      toast.error("Unable to reorder members", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
