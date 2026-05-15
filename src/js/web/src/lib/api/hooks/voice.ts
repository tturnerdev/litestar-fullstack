import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  createExtension,
  createForwardingRule,
  createPhoneNumber,
  deleteExtension,
  deleteForwardingRule,
  deletePhoneNumber,
  deleteVoicemailMessage,
  getDndSettings,
  getExtension,
  getPhoneNumber,
  getVoicemailSettings,
  listExtensions,
  listForwardingRules,
  listPhoneNumbers,
  listUnregisteredE911PhoneNumbers,
  listVoicemailMessages,
  syncExtensions,
  toggleDnd,
  updateDndSettings,
  updateExtension,
  updateForwardingRule,
  updatePhoneNumber,
  updateVoicemailMessage,
  updateVoicemailSettings,
} from "@/lib/generated/api"
import { client } from "@/lib/generated/api/client.gen"

// ---------------------------------------------------------------------------
// Re-exported generated types
// ---------------------------------------------------------------------------

// VoicemailMessage for voice extension endpoints uses VoiceSchemasVoicemailVoicemailMessage
export type {
  DndSettings,
  DndSettingsUpdate,
  DndToggleResponse,
  Extension,
  ExtensionCreate,
  ExtensionSyncResult,
  ExtensionUpdate,
  ForwardingRule,
  ForwardingRuleCreate,
  ForwardingRuleUpdate,
  PhoneNumber,
  PhoneNumberCreate,
  PhoneNumberUpdate,
  VoicemailSettings,
  VoicemailSettingsUpdate,
  VoiceSchemasVoicemailVoicemailMessage as VoicemailMessage,
} from "@/lib/generated/api"

// ---------------------------------------------------------------------------
// Phone Numbers
// ---------------------------------------------------------------------------

export function usePhoneNumbers(page = 1, pageSize = 25, options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["voice", "phone-numbers", page, pageSize],
    queryFn: () => listPhoneNumbers({ query: { currentPage: page, pageSize } }).then((r) => r.data),
    enabled: options?.enabled,
  })
}

export function usePhoneNumber(id: string) {
  return useQuery({
    queryKey: ["voice", "phone-number", id],
    queryFn: () => getPhoneNumber({ path: { phone_number_id: id } }).then((r) => r.data),
    enabled: !!id,
  })
}

export function useUpdatePhoneNumber(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: import("@/lib/generated/api").PhoneNumberUpdate) => updatePhoneNumber({ path: { phone_number_id: id }, body: payload }).then((r) => r.data),
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
    mutationFn: (payload: import("@/lib/generated/api").PhoneNumberCreate) => createPhoneNumber({ body: payload }).then((r) => r.data),
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
    mutationFn: (phoneNumberId: string) => deletePhoneNumber({ path: { phone_number_id: phoneNumberId } }).then((r) => r.data),
    onSuccess: (_data, phoneNumberId) => {
      queryClient.invalidateQueries({ queryKey: ["voice", "phone-numbers"] })
      queryClient.invalidateQueries({ queryKey: ["voice", "phone-number", phoneNumberId] })
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
    queryFn: () => listUnregisteredE911PhoneNumbers({ query: { teamId } }).then((r) => r.data),
    enabled: !!teamId,
  })
}

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

export function useExtensions(page = 1, pageSize = 25, refetchInterval?: number | false, options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["voice", "extensions", page, pageSize],
    queryFn: () => listExtensions({ query: { currentPage: page, pageSize } }).then((r) => r.data),
    refetchInterval,
    enabled: options?.enabled,
  })
}

export function useExtensionsByPhoneNumber(phoneNumberId: string) {
  return useQuery({
    queryKey: ["voice", "extensions", "by-phone-number", phoneNumberId],
    queryFn: async () => {
      const response = await listExtensions({ query: { pageSize: 100 } }).then((r) => r.data)
      return (response?.items ?? []).filter((ext) => ext.phoneNumberId === phoneNumberId)
    },
    enabled: !!phoneNumberId,
  })
}

export function useExtensionsByTeam(memberUserIds: string[]) {
  return useQuery({
    queryKey: ["voice", "extensions", "by-team", memberUserIds],
    queryFn: async () => {
      const response = await listExtensions({ query: { pageSize: 200 } }).then((r) => r.data)
      const userIdSet = new Set(memberUserIds)
      return (response?.items ?? []).filter((ext) => userIdSet.has(ext.userId))
    },
    enabled: memberUserIds.length > 0,
  })
}

export function useExtension(id: string) {
  return useQuery({
    queryKey: ["voice", "extension", id],
    queryFn: () => getExtension({ path: { ext_id: id } }).then((r) => r.data),
    enabled: !!id,
  })
}

export function useCreateExtension() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: import("@/lib/generated/api").ExtensionCreate) => createExtension({ body: payload }).then((r) => r.data),
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
    mutationFn: () => syncExtensions().then((r) => r.data),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["voice", "extensions"] })
      const created = data?.created ?? 0
      const updated = data?.updated ?? 0
      const errors = data?.errors ?? []
      const connectionName = data?.connectionName ?? null
      const parts = []
      if (created > 0) parts.push(`${created} created`)
      if (updated > 0) parts.push(`${updated} updated`)
      toast.success(`PBX sync complete${connectionName ? ` (${connectionName})` : ""}`, {
        description: parts.join(", ") || "No changes needed",
      })
      if (errors.length > 0) {
        toast.warning(`${errors.length} error(s) during sync`, {
          description: errors.slice(0, 3).join("; "),
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
    mutationFn: (payload: import("@/lib/generated/api").ExtensionUpdate) => updateExtension({ path: { ext_id: id }, body: payload }).then((r) => r.data),
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
    mutationFn: (extensionId: string) => deleteExtension({ path: { ext_id: extensionId } }).then((r) => r.data),
    onSuccess: (_data, extensionId) => {
      queryClient.invalidateQueries({ queryKey: ["voice", "extensions"] })
      queryClient.invalidateQueries({ queryKey: ["voice", "extension", extensionId] })
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
    mutationFn: ({ extensionId, payload }: { extensionId: string; payload: import("@/lib/generated/api").ExtensionUpdate }) =>
      updateExtension({ path: { ext_id: extensionId }, body: payload }).then((r) => r.data),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["voice", "extensions"] })
      queryClient.invalidateQueries({ queryKey: ["voice", "extension", variables.extensionId] })
      toast.success("Extension updated")
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
    queryFn: () => getVoicemailSettings({ path: { ext_id: extensionId } }).then((r) => r.data),
    enabled: !!extensionId,
  })
}

export function useUpdateVoicemailSettings(extensionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: import("@/lib/generated/api").VoicemailSettingsUpdate) => updateVoicemailSettings({ path: { ext_id: extensionId }, body: payload }).then((r) => r.data),
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
    queryFn: () =>
      listVoicemailMessages({
        path: { ext_id: extensionId },
        query: { currentPage: page, pageSize },
      }).then((r) => r.data),
    enabled: !!extensionId,
  })
}

export function useDeleteVoicemailMessage(extensionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (messageId: string) => deleteVoicemailMessage({ path: { ext_id: extensionId, msg_id: messageId } }).then((r) => r.data),
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
    mutationFn: ({ messageId, isRead }: { messageId: string; isRead: boolean }) =>
      updateVoicemailMessage({
        path: { ext_id: extensionId, msg_id: messageId },
        body: { isRead },
      }).then((r) => r.data),
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
    queryFn: () => listForwardingRules({ path: { ext_id: extensionId } }).then((r) => r.data),
    enabled: !!extensionId,
  })
}

export function useCreateForwardingRule(extensionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: import("@/lib/generated/api").ForwardingRuleCreate) => createForwardingRule({ path: { ext_id: extensionId }, body: payload }).then((r) => r.data),
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
    mutationFn: ({ ruleId, payload }: { ruleId: string; payload: import("@/lib/generated/api").ForwardingRuleUpdate }) =>
      updateForwardingRule({
        path: { ext_id: extensionId, rule_id: ruleId },
        body: payload,
      }).then((r) => r.data),
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
    mutationFn: (ruleId: string) => deleteForwardingRule({ path: { ext_id: extensionId, rule_id: ruleId } }).then((r) => r.data),
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
    queryFn: () => getDndSettings({ path: { ext_id: extensionId } }).then((r) => r.data),
    enabled: !!extensionId,
  })
}

export function useUpdateDndSettings(extensionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: import("@/lib/generated/api").DndSettingsUpdate) => updateDndSettings({ path: { ext_id: extensionId }, body: payload }).then((r) => r.data),
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
    mutationFn: () => toggleDnd({ path: { ext_id: extensionId } }).then((r) => r.data),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["voice", "dnd", extensionId] })
      toast.success(data?.isEnabled ? "DND enabled" : "DND disabled")
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
          updateVoicemailMessage({
            path: { ext_id: extensionId, msg_id: messageId },
            body: { isRead: true },
          }),
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
      await Promise.all(messageIds.map((messageId) => deleteVoicemailMessage({ path: { ext_id: extensionId, msg_id: messageId } })))
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
