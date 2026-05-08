import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  closeTicket as closeTicketApi,
  createTicketMessage as createMessageApi,
  createTicket as createTicketApi,
  deleteTicketMessage as deleteMessageApi,
  deleteTicket as deleteTicketApi,
  getTicket,
  listTicketMessages,
  listTickets,
  reopenTicket as reopenTicketApi,
  type Ticket,
  type TicketAttachment,
  type TicketCreate,
  type TicketMessage,
  type TicketUpdate,
  type TicketUser,
  updateTicket as updateTicketApi,
} from "@/lib/generated/api"
import { client } from "@/lib/generated/api/client.gen"

export type { Ticket, TicketAttachment, TicketCreate, TicketMessage, TicketUpdate, TicketUser }

export interface PastedImage {
  id: string
  url: string
  fileName: string
}

export interface TicketFilters {
  status?: string
  priority?: string
  category?: string
  search?: string
  orderBy?: string
  sortOrder?: string
}

// ── Ticket Hooks ───────────────────────────────────────────────────────

export function useTickets(page = 1, pageSize = 25, filters?: TicketFilters, refetchInterval?: number | false) {
  return useQuery({
    queryKey: ["support", "tickets", page, pageSize, filters],
    queryFn: async () => {
      const response = await listTickets({
        query: {
          currentPage: page,
          pageSize,
          searchString: filters?.search,
          orderBy: filters?.orderBy,
          sortOrder: filters?.sortOrder as "asc" | "desc" | undefined,
        },
      })
      return response.data as { items: Ticket[]; total: number }
    },
    refetchInterval,
  })
}

export function useTicket(ticketId: string) {
  return useQuery({
    queryKey: ["support", "ticket", ticketId],
    queryFn: async () => {
      const response = await getTicket({
        path: { ticket_id: ticketId },
      })
      return response.data as Ticket
    },
    enabled: !!ticketId,
  })
}

export function useCreateTicket() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: TicketCreate) => {
      const response = await createTicketApi({ body: payload })
      return response.data as Ticket
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["support", "tickets"] })
      toast.success("Ticket created")
    },
    onError: (error) => {
      toast.error("Unable to create ticket", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUpdateTicket(ticketId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: TicketUpdate) => {
      const response = await updateTicketApi({
        path: { ticket_id: ticketId },
        body: payload,
      })
      return response.data as Ticket
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["support", "tickets"] })
      queryClient.invalidateQueries({ queryKey: ["support", "ticket", ticketId] })
      toast.success("Ticket updated")
    },
    onError: (error) => {
      toast.error("Unable to update ticket", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useCloseTicket(ticketId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      const response = await closeTicketApi({
        path: { ticket_id: ticketId },
      })
      return response.data as Ticket
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["support", "tickets"] })
      queryClient.invalidateQueries({ queryKey: ["support", "ticket", ticketId] })
      toast.success("Ticket closed")
    },
    onError: (error) => {
      toast.error("Unable to close ticket", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useReopenTicket(ticketId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      const response = await reopenTicketApi({
        path: { ticket_id: ticketId },
      })
      return response.data as Ticket
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["support", "tickets"] })
      queryClient.invalidateQueries({ queryKey: ["support", "ticket", ticketId] })
      toast.success("Ticket reopened")
    },
    onError: (error) => {
      toast.error("Unable to reopen ticket", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteTicket(ticketId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      await deleteTicketApi({
        path: { ticket_id: ticketId },
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["support", "tickets"] })
      queryClient.removeQueries({ queryKey: ["support", "ticket", ticketId] })
      toast.success("Ticket deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete ticket", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ── Message Hooks ──────────────────────────────────────────────────────

export function useTicketMessages(ticketId: string) {
  return useQuery({
    queryKey: ["support", "ticket", ticketId, "messages"],
    queryFn: async () => {
      const response = await listTicketMessages({
        path: { ticket_id: ticketId },
      })
      return response.data as TicketMessage[]
    },
    enabled: !!ticketId,
  })
}

export function useCreateTicketMessage(ticketId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: { bodyMarkdown: string; isInternalNote?: boolean }) => {
      const response = await createMessageApi({
        path: { ticket_id: ticketId },
        body: payload,
      })
      return response.data as TicketMessage
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["support", "ticket", ticketId, "messages"] })
      queryClient.invalidateQueries({ queryKey: ["support", "ticket", ticketId] })
      queryClient.invalidateQueries({ queryKey: ["support", "tickets"] })
      toast.success("Message sent")
    },
    onError: (error) => {
      toast.error("Unable to send message", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteTicketMessage(ticketId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (messageId: string) => {
      await deleteMessageApi({
        path: { ticket_id: ticketId, msg_id: messageId },
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["support", "ticket", ticketId, "messages"] })
      queryClient.invalidateQueries({ queryKey: ["support", "ticket", ticketId] })
      queryClient.invalidateQueries({ queryKey: ["support", "tickets"] })
      toast.success("Message deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete message", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ── Attachment Hooks (raw client — generated SDK lacks multipart body) ─

export function useUploadAttachment(ticketId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (files: File[]) => {
      const formData = new FormData()
      for (const file of files) {
        formData.append("files", file)
      }
      const response = await client.post({
        url: `/api/support/tickets/${ticketId}/attachments`,
        body: formData,
        bodySerializer: (body: unknown) => body as FormData,
        headers: {},
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as TicketAttachment[]
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["support", "ticket", ticketId, "messages"] })
      toast.success("File uploaded")
    },
    onError: (error) => {
      toast.error("Unable to upload file", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function usePasteImage(ticketId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (blob: Blob) => {
      const formData = new FormData()
      formData.append("image", blob, `paste-${Date.now()}.png`)
      const response = await client.post({
        url: `/api/support/tickets/${ticketId}/paste-image`,
        body: formData,
        bodySerializer: (body: unknown) => body as FormData,
        headers: {},
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as PastedImage
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["support", "ticket", ticketId, "messages"] })
      toast.success("Image uploaded")
    },
    onError: (error) => {
      toast.error("Unable to upload image", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
