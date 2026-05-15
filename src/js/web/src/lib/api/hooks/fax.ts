import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  createFaxEmailRoute,
  createFaxNumber,
  deleteFaxEmailRoute,
  deleteFaxMessage,
  deleteFaxNumber,
  getFaxMessage,
  getFaxNumber,
  listFaxEmailRoutes,
  listFaxMessages,
  listFaxNumbers,
  sendFax,
  updateFaxEmailRoute,
  updateFaxNumber,
} from "@/lib/generated/api"

// ---------------------------------------------------------------------------
// Re-exported generated types
// ---------------------------------------------------------------------------

export type {
  FaxEmailRoute,
  FaxEmailRouteCreate,
  FaxEmailRouteUpdate,
  FaxMessage,
  FaxNumber,
  FaxNumberCreate,
  FaxNumberUpdate,
  SendFax,
} from "@/lib/generated/api"

import type { FaxEmailRoute, FaxEmailRouteUpdate, FaxNumber, FaxNumberUpdate, SendFax } from "@/lib/generated/api"

// ---------------------------------------------------------------------------
// Local composite type
// ---------------------------------------------------------------------------

export interface FaxEmailRouteWithNumber extends FaxEmailRoute {
  faxNumber: string
  faxNumberLabel: string | null
}

// ---------------------------------------------------------------------------
// Fax Numbers
// ---------------------------------------------------------------------------

export function useCreateFaxNumber() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: Parameters<typeof createFaxNumber>[0]["body"]) => {
      const response = await createFaxNumber({ body: payload })
      return response.data as Required<FaxNumber>
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

export function useFaxNumbers(page = 1, pageSize = 25, options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["fax", "numbers", page, pageSize],
    queryFn: async () => {
      const response = await listFaxNumbers({ query: { currentPage: page, pageSize } })
      return response.data
    },
    enabled: options?.enabled,
  })
}

export function useFaxNumber(id: string) {
  return useQuery({
    queryKey: ["fax", "number", id],
    queryFn: async () => {
      const response = await getFaxNumber({ path: { fax_number_id: id } })
      return response.data as Required<FaxNumber>
    },
    enabled: !!id,
  })
}

export function useUpdateFaxNumber(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: FaxNumberUpdate) => {
      const response = await updateFaxNumber({ path: { fax_number_id: id }, body: payload })
      return response.data as Required<FaxNumber>
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
      await deleteFaxNumber({ path: { fax_number_id: faxNumberId } })
    },
    onSuccess: (_data, faxNumberId) => {
      queryClient.invalidateQueries({ queryKey: ["fax", "numbers"] })
      queryClient.invalidateQueries({ queryKey: ["fax", "number", faxNumberId] })
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
      const response = await listFaxEmailRoutes({
        path: { fax_number_id: faxNumberId },
        query: { currentPage: page, pageSize },
      })
      return response.data
    },
    enabled: !!faxNumberId,
  })
}

export function useCreateFaxEmailRoute(faxNumberId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: Parameters<typeof createFaxEmailRoute>[0]["body"]) => {
      const response = await createFaxEmailRoute({ path: { fax_number_id: faxNumberId }, body: payload })
      return response.data as Required<FaxEmailRoute>
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
    mutationFn: async (payload: FaxEmailRouteUpdate) => {
      const response = await updateFaxEmailRoute({
        path: { fax_number_id: faxNumberId, route_id: routeId },
        body: payload,
      })
      return response.data as Required<FaxEmailRoute>
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
      await deleteFaxEmailRoute({ path: { fax_number_id: faxNumberId, route_id: routeId } })
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
  search?: string
  orderBy?: string
  sortOrder?: "asc" | "desc"
  /** When set, the query will automatically refetch on this interval (ms). */
  refetchInterval?: number | false
}) {
  const { page = 1, pageSize = 25, search, orderBy, sortOrder, refetchInterval } = params
  return useQuery({
    queryKey: ["fax", "messages", page, pageSize, search, orderBy, sortOrder],
    queryFn: async () => {
      const response = await listFaxMessages({
        query: {
          currentPage: page,
          pageSize,
          ...(search ? { searchString: search } : {}),
          ...(orderBy ? { orderBy } : {}),
          ...(sortOrder ? { sortOrder } : {}),
        },
      })
      return response.data
    },
    ...(refetchInterval !== undefined ? { refetchInterval } : {}),
  })
}

export function useFaxMessage(id: string) {
  return useQuery({
    queryKey: ["fax", "message", id],
    queryFn: async () => {
      const response = await getFaxMessage({ path: { message_id: id } })
      return response.data
    },
    enabled: !!id,
  })
}

export function useDeleteFaxMessage() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (messageId: string) => {
      await deleteFaxMessage({ path: { message_id: messageId } })
    },
    onSuccess: (_data, messageId) => {
      queryClient.invalidateQueries({ queryKey: ["fax", "messages"] })
      queryClient.invalidateQueries({ queryKey: ["fax", "message", messageId] })
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

export function useAllFaxEmailRoutes() {
  return useQuery({
    queryKey: ["fax", "emailRoutes", "all"],
    queryFn: async () => {
      const numbersResp = await listFaxNumbers({ query: { currentPage: 1, pageSize: 200 } })
      const numbers = numbersResp.data?.items ?? []
      const allRoutes: FaxEmailRouteWithNumber[] = []
      for (const num of numbers) {
        const routesResp = await listFaxEmailRoutes({
          path: { fax_number_id: num.id },
          query: { currentPage: 1, pageSize: 200 },
        })
        for (const route of routesResp.data?.items ?? []) {
          allRoutes.push({
            ...route,
            faxNumber: num.number,
            faxNumberLabel: num.label ?? null,
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
    mutationFn: async (payload: SendFax) => {
      const response = await sendFax({ body: payload })
      return response.data
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
