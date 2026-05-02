import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { client } from "@/lib/generated/api/client.gen"

// ---------------------------------------------------------------------------
// Helpers
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
// Types — Time Conditions
// ---------------------------------------------------------------------------

export interface TimeCondition {
  id: string
  teamId: string
  name: string
  matchDestination: string
  noMatchDestination: string
  overrideMode: string
  scheduleId: string | null
}

export interface TimeConditionCreate {
  name: string
  matchDestination: string
  noMatchDestination: string
  scheduleId?: string | null
  overrideMode?: string
}

export interface TimeConditionUpdate {
  name?: string
  matchDestination?: string
  noMatchDestination?: string
  scheduleId?: string | null
  overrideMode?: string
}

// ---------------------------------------------------------------------------
// Types — IVR Menus
// ---------------------------------------------------------------------------

export interface IvrMenuOption {
  id: string
  ivrMenuId: string
  digit: string
  label: string
  destination: string
  sortOrder: number
}

export interface IvrMenuOptionCreate {
  digit: string
  label: string
  destination: string
  sortOrder?: number
}

export interface IvrMenuOptionUpdate {
  digit?: string
  label?: string
  destination?: string
  sortOrder?: number
}

export interface IvrMenu {
  id: string
  teamId: string
  name: string
  greetingType: string
  timeoutSeconds: number
  maxRetries: number
  greetingText: string | null
  greetingFileUrl: string | null
  timeoutDestination: string | null
  invalidDestination: string | null
  options: IvrMenuOption[]
}

export interface IvrMenuCreate {
  name: string
  greetingType?: string
  greetingText?: string | null
  greetingFileUrl?: string | null
  timeoutSeconds?: number
  maxRetries?: number
  timeoutDestination?: string | null
  invalidDestination?: string | null
}

export interface IvrMenuUpdate {
  name?: string
  greetingType?: string
  greetingText?: string | null
  greetingFileUrl?: string | null
  timeoutSeconds?: number
  maxRetries?: number
  timeoutDestination?: string | null
  invalidDestination?: string | null
}

// ---------------------------------------------------------------------------
// Types — Call Queues
// ---------------------------------------------------------------------------

export interface CallQueueMember {
  id: string
  callQueueId: string
  priority: number
  penalty: number
  isPaused: boolean
  extensionId: string | null
}

export interface CallQueueMemberCreate {
  extensionId?: string | null
  priority?: number
  penalty?: number
  isPaused?: boolean
}

export interface CallQueue {
  id: string
  teamId: string
  name: string
  number: string
  strategy: string
  ringTime: number
  maxWaitTime: number
  maxCallers: number
  joinEmpty: boolean
  leaveWhenEmpty: boolean
  announceHoldtime: boolean
  wrapupTime: number
  musicOnHoldClass: string | null
  announceFrequency: number | null
  timeoutDestination: string | null
  members: CallQueueMember[]
}

export interface CallQueueCreate {
  name: string
  number: string
  strategy?: string
  ringTime?: number
  maxWaitTime?: number
  maxCallers?: number
  joinEmpty?: boolean
  leaveWhenEmpty?: boolean
  musicOnHoldClass?: string | null
  announceFrequency?: number | null
  announceHoldtime?: boolean
  timeoutDestination?: string | null
  wrapupTime?: number
}

export interface CallQueueUpdate {
  name?: string
  number?: string
  strategy?: string
  ringTime?: number
  maxWaitTime?: number
  maxCallers?: number
  joinEmpty?: boolean
  leaveWhenEmpty?: boolean
  musicOnHoldClass?: string | null
  announceFrequency?: number | null
  announceHoldtime?: boolean
  timeoutDestination?: string | null
  wrapupTime?: number
}

// ---------------------------------------------------------------------------
// Types — Ring Groups
// ---------------------------------------------------------------------------

export interface RingGroupMember {
  id: string
  ringGroupId: string
  sortOrder: number
  extensionId: string | null
  externalNumber: string | null
}

export interface RingGroupMemberCreate {
  extensionId?: string | null
  externalNumber?: string | null
  sortOrder?: number
}

export interface RingGroup {
  id: string
  teamId: string
  name: string
  number: string
  strategy: string
  ringTime: number
  noAnswerDestination: string | null
  members: RingGroupMember[]
}

export interface RingGroupCreate {
  name: string
  number: string
  strategy?: string
  ringTime?: number
  noAnswerDestination?: string | null
}

export interface RingGroupUpdate {
  name?: string
  number?: string
  strategy?: string
  ringTime?: number
  noAnswerDestination?: string | null
}

// ---------------------------------------------------------------------------
// Common
// ---------------------------------------------------------------------------

interface PaginatedResponse<T> {
  items: T[]
  total: number
}

export interface UseListOptions {
  page?: number
  pageSize?: number
  search?: string
  orderBy?: string
  sortOrder?: "asc" | "desc"
}

function buildListParams(opts: UseListOptions): string {
  const params = new URLSearchParams()
  params.set("currentPage", String(opts.page ?? 1))
  params.set("pageSize", String(opts.pageSize ?? 25))
  if (opts.search) {
    params.set("searchString", opts.search)
    params.set("searchIgnoreCase", "true")
  }
  if (opts.orderBy) params.set("orderBy", opts.orderBy)
  if (opts.sortOrder) params.set("sortOrder", opts.sortOrder)
  return params.toString()
}

// ===========================================================================
// Time Conditions
// ===========================================================================

export function useTimeConditions(opts: UseListOptions = {}) {
  return useQuery({
    queryKey: ["call-routing", "time-conditions", opts.page, opts.pageSize, opts.search, opts.orderBy, opts.sortOrder],
    queryFn: () => apiFetch<PaginatedResponse<TimeCondition>>(`/api/time-conditions?${buildListParams(opts)}`),
  })
}

export function useTimeCondition(id: string) {
  return useQuery({
    queryKey: ["call-routing", "time-condition", id],
    queryFn: () => apiFetch<TimeCondition>(`/api/time-conditions/${id}`),
    enabled: !!id,
  })
}

export function useCreateTimeCondition() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: TimeConditionCreate) =>
      apiFetch<TimeCondition>("/api/time-conditions", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
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
    mutationFn: (payload: TimeConditionUpdate) =>
      apiFetch<TimeCondition>(`/api/time-conditions/${id}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      }),
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
    mutationFn: (id: string) =>
      apiFetch<void>(`/api/time-conditions/${id}`, { method: "DELETE" }),
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
      apiFetch<TimeCondition>(`/api/time-conditions/${id}/override`, {
        method: "PUT",
        body: JSON.stringify({ overrideMode }),
      }),
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
    queryFn: () => apiFetch<PaginatedResponse<IvrMenu>>(`/api/ivr-menus?${buildListParams(opts)}`),
  })
}

export function useIvrMenu(id: string) {
  return useQuery({
    queryKey: ["call-routing", "ivr-menu", id],
    queryFn: () => apiFetch<IvrMenu>(`/api/ivr-menus/${id}`),
    enabled: !!id,
  })
}

export function useCreateIvrMenu() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: IvrMenuCreate) =>
      apiFetch<IvrMenu>("/api/ivr-menus", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
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
    mutationFn: (payload: IvrMenuUpdate) =>
      apiFetch<IvrMenu>(`/api/ivr-menus/${id}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      }),
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
    mutationFn: (id: string) =>
      apiFetch<void>(`/api/ivr-menus/${id}`, { method: "DELETE" }),
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
    mutationFn: (payload: IvrMenuOptionCreate) =>
      apiFetch<IvrMenuOption>(`/api/ivr-menus/${menuId}/options`, {
        method: "POST",
        body: JSON.stringify(payload),
      }),
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

export function useUpdateIvrMenuOption(menuId: string, optionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: IvrMenuOptionUpdate) =>
      apiFetch<IvrMenuOption>(`/api/ivr-menus/${menuId}/options/${optionId}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "ivr-menu", menuId] })
      toast.success("Option updated")
    },
    onError: (error) => {
      toast.error("Unable to update option", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteIvrMenuOption(menuId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (optionId: string) =>
      apiFetch<void>(`/api/ivr-menus/${menuId}/options/${optionId}`, { method: "DELETE" }),
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
        apiFetch<IvrMenuOption>(`/api/ivr-menus/${menuId}/options/${optionA.id}`, {
          method: "PATCH",
          body: JSON.stringify({ sortOrder: optionB.sortOrder }),
        }),
        apiFetch<IvrMenuOption>(`/api/ivr-menus/${menuId}/options/${optionB.id}`, {
          method: "PATCH",
          body: JSON.stringify({ sortOrder: optionA.sortOrder }),
        }),
      ])
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "ivr-menu", menuId] })
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
    queryFn: () => apiFetch<PaginatedResponse<CallQueue>>(`/api/call-queues?${buildListParams(opts)}`),
  })
}

export function useCallQueue(id: string) {
  return useQuery({
    queryKey: ["call-routing", "call-queue", id],
    queryFn: () => apiFetch<CallQueue>(`/api/call-queues/${id}`),
    enabled: !!id,
  })
}

export function useCreateCallQueue() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: CallQueueCreate) =>
      apiFetch<CallQueue>("/api/call-queues", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
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
    mutationFn: (payload: CallQueueUpdate) =>
      apiFetch<CallQueue>(`/api/call-queues/${id}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      }),
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
    mutationFn: (id: string) =>
      apiFetch<void>(`/api/call-queues/${id}`, { method: "DELETE" }),
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
    mutationFn: (payload: CallQueueMemberCreate) =>
      apiFetch<CallQueueMember>(`/api/call-queues/${queueId}/members`, {
        method: "POST",
        body: JSON.stringify(payload),
      }),
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
    mutationFn: (memberId: string) =>
      apiFetch<void>(`/api/call-queues/${queueId}/members/${memberId}`, { method: "DELETE" }),
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
      apiFetch<CallQueueMember>(`/api/call-queues/${queueId}/members/${memberId}/pause`, {
        method: "PUT",
        body: JSON.stringify({ isPaused }),
      }),
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
        apiFetch<CallQueueMember>(`/api/call-queues/${queueId}/members/${memberA.id}`, {
          method: "PATCH",
          body: JSON.stringify({ priority: memberB.priority }),
        }),
        apiFetch<CallQueueMember>(`/api/call-queues/${queueId}/members/${memberB.id}`, {
          method: "PATCH",
          body: JSON.stringify({ priority: memberA.priority }),
        }),
      ])
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "call-queue", queueId] })
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
    queryFn: () => apiFetch<PaginatedResponse<RingGroup>>(`/api/ring-groups?${buildListParams(opts)}`),
  })
}

export function useRingGroup(id: string) {
  return useQuery({
    queryKey: ["call-routing", "ring-group", id],
    queryFn: () => apiFetch<RingGroup>(`/api/ring-groups/${id}`),
    enabled: !!id,
  })
}

export function useCreateRingGroup() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: RingGroupCreate) =>
      apiFetch<RingGroup>("/api/ring-groups", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
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
    mutationFn: (payload: RingGroupUpdate) =>
      apiFetch<RingGroup>(`/api/ring-groups/${id}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      }),
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
    mutationFn: (id: string) =>
      apiFetch<void>(`/api/ring-groups/${id}`, { method: "DELETE" }),
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
    mutationFn: (payload: RingGroupMemberCreate) =>
      apiFetch<RingGroupMember>(`/api/ring-groups/${groupId}/members`, {
        method: "POST",
        body: JSON.stringify(payload),
      }),
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
    mutationFn: (memberId: string) =>
      apiFetch<void>(`/api/ring-groups/${groupId}/members/${memberId}`, { method: "DELETE" }),
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
        apiFetch<RingGroupMember>(`/api/ring-groups/${groupId}/members/${memberA.id}`, {
          method: "PATCH",
          body: JSON.stringify({ sortOrder: memberB.sortOrder }),
        }),
        apiFetch<RingGroupMember>(`/api/ring-groups/${groupId}/members/${memberB.id}`, {
          method: "PATCH",
          body: JSON.stringify({ sortOrder: memberA.sortOrder }),
        }),
      ])
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-routing", "ring-group", groupId] })
    },
    onError: (error) => {
      toast.error("Unable to reorder members", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
