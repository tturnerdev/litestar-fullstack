import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { client } from "@/lib/generated/api/client.gen"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PhoneNumber {
  id: string
  userId: string
  number: string
  label: string | null
  numberType: "local" | "toll_free" | "international"
  callerIdName: string | null
  isActive: boolean
  teamId: string | null
  e911Registered: boolean
  e911RegistrationId: string | null
}

export interface Extension {
  id: string
  userId: string
  extensionNumber: string
  phoneNumberId: string | null
  displayName: string
  isActive: boolean
  forwardAlwaysEnabled: boolean
  forwardAlwaysDestination: string | null
  forwardBusyEnabled: boolean
  forwardBusyDestination: string | null
  forwardNoAnswerEnabled: boolean
  forwardNoAnswerDestination: string | null
  forwardNoAnswerRingCount: number
  forwardUnreachableEnabled: boolean
  forwardUnreachableDestination: string | null
  dndEnabled: boolean
  e911Status: string
  e911RegistrationId: string | null
  createdAt: string | null
  updatedAt: string | null
}

export interface VoicemailSettings {
  id: string
  extensionId: string
  isEnabled: boolean
  greetingType: "default" | "custom" | "name_only"
  greetingFilePath: string | null
  maxMessageLengthSeconds: number
  emailAddress: string | null
  emailNotification: boolean
  emailAttachAudio: boolean
  transcriptionEnabled: boolean
  autoDeleteDays: number | null
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
}

export interface ForwardingRule {
  id: string
  extensionId: string
  ruleType: "always" | "busy" | "no_answer" | "unreachable"
  destinationType: "extension" | "external" | "voicemail"
  destinationValue: string
  ringTimeoutSeconds: number | null
  isActive: boolean
  priority: number
}

export interface DndSettings {
  id: string
  extensionId: string
  isEnabled: boolean
  mode: "always" | "scheduled" | "off"
  scheduleStart: string | null
  scheduleEnd: string | null
  scheduleDays: number[] | null
  allowList: string[] | null
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
// Phone Numbers
// ---------------------------------------------------------------------------

export function usePhoneNumbers(page = 1, pageSize = 25) {
  return useQuery({
    queryKey: ["voice", "phone-numbers", page, pageSize],
    queryFn: () => apiFetch<PaginatedResponse<PhoneNumber>>(`/api/voice/phone-numbers?currentPage=${page}&pageSize=${pageSize}`),
  })
}

export function usePhoneNumber(id: string) {
  return useQuery({
    queryKey: ["voice", "phone-number", id],
    queryFn: () => apiFetch<PhoneNumber>(`/api/voice/phone-numbers/${id}`),
    enabled: !!id,
  })
}

export function useUpdatePhoneNumber(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      apiFetch<PhoneNumber>(`/api/voice/phone-numbers/${id}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "phone-numbers"] })
      queryClient.invalidateQueries({ queryKey: ["voice", "phone-number", id] })
      toast.success("Phone number updated")
    },
    onError: (error) => {
      toast.error("Unable to update phone number", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useCreatePhoneNumber() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      apiFetch<PhoneNumber>("/api/voice/phone-numbers", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "phone-numbers"] })
      toast.success("Phone number created")
    },
    onError: (error) => {
      toast.error("Unable to create phone number", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeletePhoneNumber() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (phoneNumberId: string) =>
      apiFetch<void>(`/api/voice/phone-numbers/${phoneNumberId}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "phone-numbers"] })
      toast.success("Phone number deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete phone number", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUnregisteredE911Numbers(teamId: string) {
  return useQuery({
    queryKey: ["voice", "phone-numbers", "unregistered-e911", teamId],
    queryFn: () => apiFetch<PhoneNumber[]>(`/api/voice/phone-numbers/unregistered-e911?teamId=${teamId}`),
    enabled: !!teamId,
  })
}

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

export function useExtensions(page = 1, pageSize = 25) {
  return useQuery({
    queryKey: ["voice", "extensions", page, pageSize],
    queryFn: () => apiFetch<PaginatedResponse<Extension>>(`/api/voice/extensions?currentPage=${page}&pageSize=${pageSize}`),
  })
}

export function useExtensionsByPhoneNumber(phoneNumberId: string) {
  return useQuery({
    queryKey: ["voice", "extensions", "by-phone-number", phoneNumberId],
    queryFn: async () => {
      const response = await apiFetch<PaginatedResponse<Extension>>("/api/voice/extensions?pageSize=100")
      return response.items.filter((ext) => ext.phoneNumberId === phoneNumberId)
    },
    enabled: !!phoneNumberId,
  })
}

export function useExtensionsByTeam(memberUserIds: string[]) {
  return useQuery({
    queryKey: ["voice", "extensions", "by-team", memberUserIds],
    queryFn: async () => {
      const response = await apiFetch<PaginatedResponse<Extension>>("/api/voice/extensions?pageSize=200")
      const userIdSet = new Set(memberUserIds)
      return response.items.filter((ext) => userIdSet.has(ext.userId))
    },
    enabled: memberUserIds.length > 0,
  })
}

export function useExtension(id: string) {
  return useQuery({
    queryKey: ["voice", "extension", id],
    queryFn: () => apiFetch<Extension>(`/api/voice/extensions/${id}`),
    enabled: !!id,
  })
}

export function useCreateExtension() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      apiFetch<Extension>("/api/voice/extensions", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "extensions"] })
      toast.success("Extension created")
    },
    onError: (error) => {
      toast.error("Unable to create extension", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useSyncExtensions() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiFetch<{ created: number; updated: number; errors: string[]; connectionName: string | null }>(
        "/api/voice/extensions/sync",
        { method: "POST" },
      ),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["voice", "extensions"] })
      const parts = []
      if (data.created > 0) parts.push(`${data.created} created`)
      if (data.updated > 0) parts.push(`${data.updated} updated`)
      toast.success(
        `PBX sync complete${data.connectionName ? ` (${data.connectionName})` : ""}`,
        { description: parts.join(", ") || "No changes needed" },
      )
      if (data.errors.length > 0) {
        toast.warning(`${data.errors.length} error(s) during sync`, {
          description: data.errors.slice(0, 3).join("; "),
        })
      }
    },
    onError: (error) => {
      toast.error("Extension sync failed", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUpdateExtension(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      apiFetch<Extension>(`/api/voice/extensions/${id}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "extensions"] })
      queryClient.invalidateQueries({ queryKey: ["voice", "extension", id] })
      toast.success("Extension updated")
    },
    onError: (error) => {
      toast.error("Unable to update extension", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteExtension() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (extensionId: string) =>
      apiFetch<void>(`/api/voice/extensions/${extensionId}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "extensions"] })
      toast.success("Extension deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete extension", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

/**
 * Update any extension by passing extensionId as part of the mutation argument.
 * Useful for bulk operations where the target extension is not known at hook call time.
 */
export function useUpdateAnyExtension() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ extensionId, payload }: { extensionId: string; payload: Record<string, unknown> }) =>
      apiFetch<Extension>(`/api/voice/extensions/${extensionId}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "extensions"] })
    },
    onError: (error) => {
      toast.error("Unable to update extension", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Voicemail Settings
// ---------------------------------------------------------------------------

export function useVoicemailSettings(extensionId: string) {
  return useQuery({
    queryKey: ["voice", "voicemail-settings", extensionId],
    queryFn: () => apiFetch<VoicemailSettings>(`/api/voice/extensions/${extensionId}/voicemail`),
    enabled: !!extensionId,
  })
}

export function useUpdateVoicemailSettings(extensionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      apiFetch<VoicemailSettings>(`/api/voice/extensions/${extensionId}/voicemail`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "voicemail-settings", extensionId] })
      toast.success("Voicemail settings updated")
    },
    onError: (error) => {
      toast.error("Unable to update voicemail settings", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Voicemail Messages
// ---------------------------------------------------------------------------

export function useVoicemailMessages(extensionId: string, page = 1, pageSize = 25) {
  return useQuery({
    queryKey: ["voice", "voicemail-messages", extensionId, page, pageSize],
    queryFn: () => apiFetch<PaginatedResponse<VoicemailMessage>>(`/api/voice/extensions/${extensionId}/voicemail/messages?currentPage=${page}&pageSize=${pageSize}`),
    enabled: !!extensionId,
  })
}

export function useUpdateVoicemailMessage(extensionId: string, messageId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      apiFetch<VoicemailMessage>(`/api/voice/extensions/${extensionId}/voicemail/messages/${messageId}`, { method: "PATCH", body: JSON.stringify(payload) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "voicemail-messages", extensionId] })
      toast.success("Message updated")
    },
    onError: (error) => {
      toast.error("Unable to update message", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteVoicemailMessage(extensionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (messageId: string) => apiFetch<void>(`/api/voice/extensions/${extensionId}/voicemail/messages/${messageId}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "voicemail-messages", extensionId] })
      toast.success("Message deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete message", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUploadVoicemailGreeting(extensionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (file: File) => {
      const config = client.getConfig()
      const baseUrl = config.baseUrl ?? ""
      const token = typeof window !== "undefined" ? window.localStorage.getItem("access_token") : null
      const formData = new FormData()
      formData.append("file", file)
      const response = await fetch(`${baseUrl}/api/voice/extensions/${extensionId}/voicemail/greeting`, {
        method: "POST",
        credentials: "include",
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: formData,
      })
      if (!response.ok) {
        const body = await response.json().catch(() => ({}))
        throw new Error(body.detail ?? `Upload failed (${response.status})`)
      }
      return response.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "voicemail-settings", extensionId] })
      toast.success("Greeting uploaded")
    },
    onError: (error) => {
      toast.error("Unable to upload greeting", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useMarkVoicemailRead(extensionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ messageId, isRead }: { messageId: string; isRead: boolean }) =>
      apiFetch<VoicemailMessage>(`/api/voice/extensions/${extensionId}/voicemail/messages/${messageId}`, {
        method: "PATCH",
        body: JSON.stringify({ isRead }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "voicemail-messages", extensionId] })
    },
    onError: (error) => {
      toast.error("Unable to update message", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Forwarding Rules
// ---------------------------------------------------------------------------

export function useForwardingRules(extensionId: string) {
  return useQuery({
    queryKey: ["voice", "forwarding-rules", extensionId],
    queryFn: () => apiFetch<PaginatedResponse<ForwardingRule>>(`/api/voice/extensions/${extensionId}/forwarding`),
    enabled: !!extensionId,
  })
}

export function useSetForwardingRules(extensionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (rules: Record<string, unknown>[]) =>
      apiFetch<ForwardingRule[]>(`/api/voice/extensions/${extensionId}/forwarding`, {
        method: "PUT",
        body: JSON.stringify(rules),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "forwarding-rules", extensionId] })
      toast.success("Forwarding rules saved")
    },
    onError: (error) => {
      toast.error("Unable to save forwarding rules", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useCreateForwardingRule(extensionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      apiFetch<ForwardingRule>(`/api/voice/extensions/${extensionId}/forwarding`, {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "forwarding-rules", extensionId] })
      toast.success("Forwarding rule created")
    },
    onError: (error) => {
      toast.error("Unable to create forwarding rule", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUpdateForwardingRule(extensionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ ruleId, payload }: { ruleId: string; payload: Record<string, unknown> }) =>
      apiFetch<ForwardingRule>(`/api/voice/extensions/${extensionId}/forwarding/${ruleId}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "forwarding-rules", extensionId] })
      toast.success("Forwarding rule updated")
    },
    onError: (error) => {
      toast.error("Unable to update forwarding rule", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteForwardingRule(extensionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (ruleId: string) =>
      apiFetch<void>(`/api/voice/extensions/${extensionId}/forwarding/${ruleId}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "forwarding-rules", extensionId] })
      toast.success("Forwarding rule deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete forwarding rule", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Do Not Disturb
// ---------------------------------------------------------------------------

export function useDndSettings(extensionId: string) {
  return useQuery({
    queryKey: ["voice", "dnd", extensionId],
    queryFn: () => apiFetch<DndSettings>(`/api/voice/extensions/${extensionId}/dnd`),
    enabled: !!extensionId,
  })
}

export function useUpdateDndSettings(extensionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      apiFetch<DndSettings>(`/api/voice/extensions/${extensionId}/dnd`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "dnd", extensionId] })
      toast.success("DND settings updated")
    },
    onError: (error) => {
      toast.error("Unable to update DND settings", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useToggleDnd(extensionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => apiFetch<{ isEnabled: boolean }>(`/api/voice/extensions/${extensionId}/dnd/toggle`, { method: "POST" }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["voice", "dnd", extensionId] })
      toast.success(data.isEnabled ? "DND enabled" : "DND disabled")
    },
    onError: (error) => {
      toast.error("Unable to toggle DND", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Bulk Operations
// ---------------------------------------------------------------------------

export function useBulkMarkVoicemailRead(extensionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (messageIds: string[]) => {
      await Promise.all(
        messageIds.map((messageId) =>
          apiFetch<VoicemailMessage>(
            `/api/voice/extensions/${extensionId}/voicemail/messages/${messageId}`,
            { method: "PATCH", body: JSON.stringify({ isRead: true }) },
          ),
        ),
      )
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "voicemail-messages", extensionId] })
      toast.success("Messages marked as read")
    },
    onError: (error) => {
      toast.error("Unable to mark messages as read", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useBulkDeleteVoicemailMessages(extensionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (messageIds: string[]) => {
      await Promise.all(
        messageIds.map((messageId) =>
          apiFetch<void>(
            `/api/voice/extensions/${extensionId}/voicemail/messages/${messageId}`,
            { method: "DELETE" },
          ),
        ),
      )
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["voice", "voicemail-messages", extensionId] })
      toast.success("Messages deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete messages", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
