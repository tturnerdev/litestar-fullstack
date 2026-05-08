import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  deleteVoicemailBox as deleteBoxApi,
  deleteVoicemailMessageById,
  getVoicemailBox,
  getVoicemailMessageById,
  listAllVoicemailMessages,
  listVoicemailBoxes,
  listVoicemailBoxMessages,
  toggleVoicemailMessageRead,
  updateVoicemailBox as updateBoxApi,
  type VoicemailBox,
  type VoicemailBoxUpdate,
  type VoicemailSchemasVoicemailMessageVoicemailMessage,
} from "@/lib/generated/api"

export type VoicemailMessage = Required<VoicemailSchemasVoicemailMessageVoicemailMessage>

export type { VoicemailBox, VoicemailBoxUpdate }

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
    queryFn: async () => {
      const response = await listVoicemailBoxes({
        query: {
          currentPage: page,
          pageSize,
          searchString: search,
        },
      })
      return response.data as { items: Required<VoicemailBox>[]; total: number }
    },
  })
}

export function useVoicemailBox(boxId: string) {
  return useQuery({
    queryKey: ["voicemail", "box", boxId],
    queryFn: async () => {
      const response = await getVoicemailBox({
        path: { box_id: boxId },
      })
      return response.data as Required<VoicemailBox>
    },
    enabled: !!boxId,
  })
}

export function useUpdateVoicemailBox(boxId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: VoicemailBoxUpdate) => {
      const response = await updateBoxApi({
        path: { box_id: boxId },
        body: payload,
      })
      return response.data as Required<VoicemailBox>
    },
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
    mutationFn: async (boxId: string) => {
      await deleteBoxApi({
        path: { box_id: boxId },
      })
    },
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
    queryFn: async () => {
      if (boxId) {
        const response = await listVoicemailBoxMessages({
          path: { box_id: boxId },
          query: { currentPage: page, pageSize },
        })
        return response.data as { items: VoicemailMessage[]; total: number }
      }
      const response = await listAllVoicemailMessages({
        query: { currentPage: page, pageSize },
      })
      return response.data as { items: VoicemailMessage[]; total: number }
    },
  })
}

export function useVoicemailMessage(messageId: string) {
  return useQuery({
    queryKey: ["voicemail", "message", messageId],
    queryFn: async () => {
      const response = await getVoicemailMessageById({
        path: { message_id: messageId },
      })
      return response.data as VoicemailMessage
    },
    enabled: !!messageId,
  })
}

export function useMarkVoicemailRead(messageId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      const response = await toggleVoicemailMessageRead({
        path: { message_id: messageId },
        body: { isRead: true },
      })
      return response.data as VoicemailMessage
    },
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
    mutationFn: async ({ messageId, isRead }: { messageId: string; isRead: boolean }) => {
      const response = await toggleVoicemailMessageRead({
        path: { message_id: messageId },
        body: { isRead },
      })
      return response.data as VoicemailMessage
    },
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
    mutationFn: async (messageId: string) => {
      await deleteVoicemailMessageById({
        path: { message_id: messageId },
      })
    },
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
          toggleVoicemailMessageRead({
            path: { message_id: messageId },
            body: { isRead: true },
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
          deleteVoicemailMessageById({
            path: { message_id: messageId },
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
