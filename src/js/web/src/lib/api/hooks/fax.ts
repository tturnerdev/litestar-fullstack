import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { client } from "@/lib/generated/api/client.gen"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FaxNumber {
  id: string
  userId: string
  teamId: string | null
  number: string
  label: string | null
  isActive: boolean
  emailRoutes?: FaxEmailRoute[]
  messageCount?: number
  createdAt: string | null
  updatedAt: string | null
}

export interface FaxEmailRoute {
  id: string
  faxNumberId: string
  emailAddress: string
  isActive: boolean
  notifyOnFailure: boolean
  createdAt: string | null
  updatedAt: string | null
}

export interface FaxMessage {
  id: string
  faxNumberId: string
  direction: "inbound" | "outbound"
  remoteNumber: string
  remoteName: string | null
  pageCount: number
  status: "queued" | "received" | "delivered" | "failed" | "sending" | "sent"
  filePath: string
  fileSizeBytes: number
  errorMessage: string | null
  deliveredToEmails: string[] | null
  receivedAt: string | null
  createdAt: string | null
  updatedAt: string | null
}

interface PaginatedResponse<T> {
  items: T[]
  total: number
}

// ---------------------------------------------------------------------------
// Fetch helpers (manual since generated client doesn't include fax yet)
// ---------------------------------------------------------------------------

async function apiFetch<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await client.request({
    method: (options?.method as "GET") ?? "GET",
    url,
    body: options?.body ? JSON.parse(options.body as string) : undefined,
  })
  return response.data as T
}

// ---------------------------------------------------------------------------
// Fax Numbers
// ---------------------------------------------------------------------------

export function useCreateFaxNumber() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: { number: string; label?: string; isActive?: boolean; teamId?: string }) => {
      return apiFetch<FaxNumber>("/api/fax/numbers", {
        method: "POST",
        body: JSON.stringify(payload),
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["fax", "numbers"] })
      toast.success("Fax number created")
    },
    onError: (error) => {
      toast.error("Unable to create fax number", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useFaxNumbers(page = 1, pageSize = 25) {
  return useQuery({
    queryKey: ["fax", "numbers", page, pageSize],
    queryFn: async () => {
      return apiFetch<PaginatedResponse<FaxNumber>>(`/api/fax/numbers?currentPage=${page}&pageSize=${pageSize}`)
    },
  })
}

export function useFaxNumber(id: string) {
  return useQuery({
    queryKey: ["fax", "number", id],
    queryFn: async () => {
      return apiFetch<FaxNumber>(`/api/fax/numbers/${id}`)
    },
    enabled: !!id,
  })
}

export function useUpdateFaxNumber(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: Record<string, unknown>) => {
      return apiFetch<FaxNumber>(`/api/fax/numbers/${id}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["fax", "numbers"] })
      queryClient.invalidateQueries({ queryKey: ["fax", "number", id] })
      toast.success("Fax number updated")
    },
    onError: (error) => {
      toast.error("Unable to update fax number", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteFaxNumber() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (faxNumberId: string) => {
      return apiFetch<void>(`/api/fax/numbers/${faxNumberId}`, {
        method: "DELETE",
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["fax", "numbers"] })
      toast.success("Fax number deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete fax number", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Email Routes
// ---------------------------------------------------------------------------

export function useFaxEmailRoutes(faxNumberId: string, page = 1, pageSize = 25) {
  return useQuery({
    queryKey: ["fax", "emailRoutes", faxNumberId, page, pageSize],
    queryFn: async () => {
      return apiFetch<PaginatedResponse<FaxEmailRoute>>(`/api/fax/numbers/${faxNumberId}/email-routes?currentPage=${page}&pageSize=${pageSize}`)
    },
    enabled: !!faxNumberId,
  })
}

export function useCreateFaxEmailRoute(faxNumberId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: { emailAddress: string; isActive?: boolean; notifyOnFailure?: boolean }) => {
      return apiFetch<FaxEmailRoute>(`/api/fax/numbers/${faxNumberId}/email-routes`, {
        method: "POST",
        body: JSON.stringify(payload),
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["fax", "emailRoutes", faxNumberId] })
      queryClient.invalidateQueries({ queryKey: ["fax", "number", faxNumberId] })
      toast.success("Email route added")
    },
    onError: (error) => {
      toast.error("Unable to add email route", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUpdateFaxEmailRoute(faxNumberId: string, routeId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: Record<string, unknown>) => {
      return apiFetch<FaxEmailRoute>(`/api/fax/numbers/${faxNumberId}/email-routes/${routeId}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["fax", "emailRoutes", faxNumberId] })
      toast.success("Email route updated")
    },
    onError: (error) => {
      toast.error("Unable to update email route", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteFaxEmailRoute(faxNumberId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (routeId: string) => {
      return apiFetch<void>(`/api/fax/numbers/${faxNumberId}/email-routes/${routeId}`, {
        method: "DELETE",
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["fax", "emailRoutes", faxNumberId] })
      queryClient.invalidateQueries({ queryKey: ["fax", "number", faxNumberId] })
      toast.success("Email route removed")
    },
    onError: (error) => {
      toast.error("Unable to remove email route", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Fax Messages
// ---------------------------------------------------------------------------

export function useFaxMessages(params: {
  page?: number
  pageSize?: number
  direction?: string
  status?: string
  search?: string
  orderBy?: string
  sortOrder?: string
  /** When set, the query will automatically refetch on this interval (ms). */
  refetchInterval?: number | false
}) {
  const { page = 1, pageSize = 25, direction, status, search, orderBy, sortOrder, refetchInterval } = params
  return useQuery({
    queryKey: ["fax", "messages", page, pageSize, direction, status, search, orderBy, sortOrder],
    queryFn: async () => {
      const searchParams = new URLSearchParams()
      searchParams.set("currentPage", String(page))
      searchParams.set("pageSize", String(pageSize))
      if (direction) searchParams.set("direction", direction)
      if (status) searchParams.set("status", status)
      if (search) searchParams.set("search", search)
      if (orderBy) searchParams.set("orderBy", orderBy)
      if (sortOrder) searchParams.set("sortOrder", sortOrder)
      return apiFetch<PaginatedResponse<FaxMessage>>(`/api/fax/messages?${searchParams.toString()}`)
    },
    ...(refetchInterval !== undefined ? { refetchInterval } : {}),
  })
}

export function useFaxMessage(id: string) {
  return useQuery({
    queryKey: ["fax", "message", id],
    queryFn: async () => {
      return apiFetch<FaxMessage>(`/api/fax/messages/${id}`)
    },
    enabled: !!id,
  })
}

export function useDeleteFaxMessage() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (messageId: string) => {
      return apiFetch<void>(`/api/fax/messages/${messageId}`, {
        method: "DELETE",
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["fax", "messages"] })
      toast.success("Fax message deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete fax message", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDownloadFaxDocument(messageId: string) {
  return useQuery({
    queryKey: ["fax", "download", messageId],
    queryFn: async () => {
      const token = window.localStorage.getItem("access_token") ?? ""
      const response = await fetch(`/api/fax/messages/${messageId}/download`, {
        credentials: "include",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      })
      if (!response.ok) {
        throw new Error("Failed to download fax document")
      }
      const blob = await response.blob()
      return URL.createObjectURL(blob)
    },
    enabled: !!messageId,
    staleTime: 5 * 60 * 1000,
  })
}

// ---------------------------------------------------------------------------
// All Email Routes (aggregated across fax numbers)
// ---------------------------------------------------------------------------

export interface FaxEmailRouteWithNumber extends FaxEmailRoute {
  faxNumber: string
  faxNumberLabel: string | null
}

export function useAllFaxEmailRoutes() {
  return useQuery({
    queryKey: ["fax", "emailRoutes", "all"],
    queryFn: async () => {
      const numbersResp = await apiFetch<PaginatedResponse<FaxNumber>>("/api/fax/numbers?currentPage=1&pageSize=200")
      const allRoutes: FaxEmailRouteWithNumber[] = []
      for (const num of numbersResp.items) {
        const routesResp = await apiFetch<PaginatedResponse<FaxEmailRoute>>(`/api/fax/numbers/${num.id}/email-routes?currentPage=1&pageSize=200`)
        for (const route of routesResp.items) {
          allRoutes.push({
            ...route,
            faxNumber: num.number,
            faxNumberLabel: num.label,
          })
        }
      }
      return allRoutes
    },
  })
}

// ---------------------------------------------------------------------------
// Send Fax
// ---------------------------------------------------------------------------

export function useSendFax() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: { faxNumberId: string; destinationNumber: string; subject?: string; body?: string }) => {
      return apiFetch<FaxMessage>("/api/fax/send", {
        method: "POST",
        body: JSON.stringify(payload),
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["fax", "messages"] })
      toast.success("Fax queued for sending")
    },
    onError: (error) => {
      toast.error("Unable to send fax", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
