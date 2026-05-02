import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { client } from "@/lib/generated/api/client.gen"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface VoicemailBox {
  id: string
  extensionId: string | null
  extensionNumber: string | null
  mailboxNumber: string
  pin: string | null
  email: string | null
  isEnabled: boolean
  greetingType: "default" | "custom" | "name_only"
  greetingFilePath: string | null
  maxMessageLengthSeconds: number
  emailNotification: boolean
  emailAttachAudio: boolean
  transcriptionEnabled: boolean
  autoDeleteDays: number | null
  unreadCount: number
  totalCount: number
  createdAt: string | null
  updatedAt: string | null
}

export interface VoicemailMessage {
  id: string
  voicemailBoxId: string
  callerNumber: string
  callerName: string | null
  durationSeconds: number
  audioFilePath: string
  transcription: string | null
  isRead: boolean
  isUrgent: boolean
  receivedAt: string
  createdAt: string | null
  updatedAt: string | null
}

interface PaginatedResponse<T> {
  items: T[]
  total: number
}

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
// Voicemail Boxes
// ---------------------------------------------------------------------------

export interface UseVoicemailBoxesOptions {
  page?: number
  pageSize?: number
  search?: string
}

export function useVoicemailBoxes(options: UseVoicemailBoxesOptions = {}) {
  const { page = 1, pageSize = 25, search } = options
  return useQuery({
    queryKey: ["voicemail", "boxes", page, pageSize, search],
    queryFn: () => {
      const params = new URLSearchParams()
      params.set("currentPage", String(page))
      params.set("pageSize", String(pageSize))
      if (search) params.set("search", search)
      return apiFetch<PaginatedResponse<VoicemailBox>>(
        `/api/voicemail/boxes?${params.toString()}`,
      )
    },
  })
}

export function useVoicemailBox(boxId: string) {
  return useQuery({
    queryKey: ["voicemail", "box", boxId],
    queryFn: () => apiFetch<VoicemailBox>(`/api/voicemail/boxes/${boxId}`),
    enabled: !!boxId,
  })
}

export function useUpdateVoicemailBox(boxId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      apiFetch<VoicemailBox>(`/api/voicemail/boxes/${boxId}`, {
        method: "PUT",
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voicemail", "boxes"] })
      queryClient.invalidateQueries({ queryKey: ["voicemail", "box", boxId] })
      toast.success("Voicemail box updated")
    },
    onError: (error) => {
      toast.error("Unable to update voicemail box", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteVoicemailBox() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (boxId: string) =>
      apiFetch<void>(`/api/voicemail/boxes/${boxId}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voicemail", "boxes"] })
      toast.success("Voicemail box deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete voicemail box", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Voicemail Messages
// ---------------------------------------------------------------------------

export interface UseVoicemailMessagesOptions {
  boxId?: string
  page?: number
  pageSize?: number
  isRead?: boolean | null
  startDate?: string
  endDate?: string
}

export function useVoicemailMessages(options: UseVoicemailMessagesOptions = {}) {
  const { boxId, page = 1, pageSize = 25, isRead, startDate, endDate } = options
  return useQuery({
    queryKey: ["voicemail", "messages", boxId, page, pageSize, isRead, startDate, endDate],
    queryFn: () => {
      const params = new URLSearchParams()
      params.set("currentPage", String(page))
      params.set("pageSize", String(pageSize))
      if (isRead !== null && isRead !== undefined) params.set("isRead", String(isRead))
      if (startDate) params.set("startDate", startDate)
      if (endDate) params.set("endDate", endDate)

      if (boxId) {
        return apiFetch<PaginatedResponse<VoicemailMessage>>(
          `/api/voicemail/boxes/${boxId}/messages?${params.toString()}`,
        )
      }
      return apiFetch<PaginatedResponse<VoicemailMessage>>(
        `/api/voicemail/messages?${params.toString()}`,
      )
    },
  })
}

export function useVoicemailMessage(messageId: string) {
  return useQuery({
    queryKey: ["voicemail", "message", messageId],
    queryFn: () => apiFetch<VoicemailMessage>(`/api/voicemail/messages/${messageId}`),
    enabled: !!messageId,
  })
}

export function useMarkVoicemailRead(messageId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiFetch<VoicemailMessage>(`/api/voicemail/messages/${messageId}/read`, {
        method: "PUT",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voicemail", "messages"] })
      queryClient.invalidateQueries({ queryKey: ["voicemail", "message", messageId] })
      queryClient.invalidateQueries({ queryKey: ["voicemail", "boxes"] })
    },
    onError: (error) => {
      toast.error("Unable to update message", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useToggleVoicemailRead() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ messageId, isRead }: { messageId: string; isRead: boolean }) =>
      apiFetch<VoicemailMessage>(`/api/voicemail/messages/${messageId}/read`, {
        method: "PUT",
        body: JSON.stringify({ isRead }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voicemail", "messages"] })
      queryClient.invalidateQueries({ queryKey: ["voicemail", "boxes"] })
    },
    onError: (error) => {
      toast.error("Unable to update message", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteVoicemailMessage() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (messageId: string) =>
      apiFetch<void>(`/api/voicemail/messages/${messageId}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voicemail", "messages"] })
      queryClient.invalidateQueries({ queryKey: ["voicemail", "boxes"] })
      toast.success("Message deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete message", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Bulk Operations
// ---------------------------------------------------------------------------

export function useBulkMarkVoicemailRead() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (messageIds: string[]) => {
      await Promise.all(
        messageIds.map((messageId) =>
          apiFetch<VoicemailMessage>(`/api/voicemail/messages/${messageId}/read`, {
            method: "PUT",
          }),
        ),
      )
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voicemail", "messages"] })
      queryClient.invalidateQueries({ queryKey: ["voicemail", "boxes"] })
      toast.success("Messages marked as read")
    },
    onError: (error) => {
      toast.error("Unable to mark messages as read", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useBulkDeleteVoicemailMessages() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (messageIds: string[]) => {
      await Promise.all(
        messageIds.map((messageId) =>
          apiFetch<void>(`/api/voicemail/messages/${messageId}`, {
            method: "DELETE",
          }),
        ),
      )
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voicemail", "messages"] })
      queryClient.invalidateQueries({ queryKey: ["voicemail", "boxes"] })
      toast.success("Messages deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete messages", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
