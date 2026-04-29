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
  status: "received" | "delivered" | "failed" | "sending" | "sent"
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

export function useFaxNumbers(page = 1, pageSize = 25) {
  return useQuery({
    queryKey: ["fax", "numbers", page, pageSize],
    queryFn: async () => {
      return apiFetch<PaginatedResponse<FaxNumber>>(
        `/api/fax/numbers?currentPage=${page}&pageSize=${pageSize}`,
      )
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
      return apiFetch<PaginatedResponse<FaxEmailRoute>>(
        `/api/fax/numbers/${faxNumberId}/email-routes?currentPage=${page}&pageSize=${pageSize}`,
      )
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
}) {
  const { page = 1, pageSize = 25, direction, status } = params
  return useQuery({
    queryKey: ["fax", "messages", page, pageSize, direction, status],
    queryFn: async () => {
      const searchParams = new URLSearchParams()
      searchParams.set("currentPage", String(page))
      searchParams.set("pageSize", String(pageSize))
      if (direction) searchParams.set("direction", direction)
      if (status) searchParams.set("status", status)
      return apiFetch<PaginatedResponse<FaxMessage>>(
        `/api/fax/messages?${searchParams.toString()}`,
      )
    },
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
// Send Fax
// ---------------------------------------------------------------------------

export function useSendFax() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: {
      faxNumberId: string
      remoteNumber: string
      file: File
    }) => {
      const formData = new FormData()
      formData.append("fax_number_id", payload.faxNumberId)
      formData.append("remote_number", payload.remoteNumber)
      formData.append("file", payload.file)
      const response = await fetch("/api/fax/send", {
        method: "POST",
        body: formData,
        credentials: "include",
        headers: {
          Authorization: `Bearer ${window.localStorage.getItem("access_token") ?? ""}`,
          ...(window.__LITESTAR_CSRF__ ? { "x-csrftoken": window.__LITESTAR_CSRF__ } : {}),
        },
      })
      if (!response.ok) {
        const detail = await response.json().catch(() => ({}))
        throw new Error(detail?.detail ?? "Failed to send fax")
      }
      return response.json()
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
