import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { client } from "@/lib/generated/api/client.gen"

// ── Types ──────────────────────────────────────────────────────────────

export interface TicketUser {
  id: string
  email: string
  name?: string | null
  avatarUrl?: string | null
}

export interface Ticket {
  id: string
  ticketNumber: string
  subject: string
  status: string
  priority: string
  category?: string | null
  isReadByUser: boolean
  isReadByAgent: boolean
  user?: TicketUser | null
  assignedTo?: TicketUser | null
  messageCount: number
  latestMessagePreview?: string | null
  createdAt?: string | null
  updatedAt?: string | null
  closedAt?: string | null
  resolvedAt?: string | null
}

export interface TicketMessage {
  id: string
  bodyMarkdown: string
  bodyHtml: string
  author?: TicketUser | null
  isInternalNote: boolean
  isSystemMessage: boolean
  isStaff?: boolean
  attachments: TicketAttachment[]
  createdAt?: string | null
  updatedAt?: string | null
}

export interface TicketAttachment {
  id: string
  fileName: string
  filePath: string
  fileSizeBytes: number
  contentType: string
  isInline: boolean
  url?: string | null
  createdAt?: string | null
}

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

export function useTickets(page = 1, pageSize = 25, filters?: TicketFilters) {
  return useQuery({
    queryKey: ["support", "tickets", page, pageSize, filters],
    queryFn: async () => {
      const query: Record<string, unknown> = { currentPage: page, pageSize }
      if (filters?.status && filters.status !== "all") query.status = filters.status
      if (filters?.priority && filters.priority !== "all") query.priority = filters.priority
      if (filters?.category && filters.category !== "all") query.category = filters.category
      if (filters?.search) query.search = filters.search
      if (filters?.orderBy) query.orderBy = filters.orderBy
      if (filters?.sortOrder) query.sortOrder = filters.sortOrder
      const response = await client.get({
        url: "/api/support/tickets",
        query,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as { items: Ticket[]; total: number }
    },
  })
}

export function useTicket(ticketId: string) {
  return useQuery({
    queryKey: ["support", "ticket", ticketId],
    queryFn: async () => {
      const response = await client.get({
        url: `/api/support/tickets/${ticketId}`,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as Ticket
    },
    enabled: !!ticketId,
  })
}

export function useCreateTicket() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: { subject: string; bodyMarkdown: string; priority?: string; category?: string | null; teamId?: string | null }) => {
      const response = await client.post({
        url: "/api/support/tickets",
        body: payload,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as Ticket
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
    mutationFn: async (payload: Record<string, unknown>) => {
      const response = await client.patch({
        url: `/api/support/tickets/${ticketId}`,
        body: payload,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as Ticket
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
      const response = await client.post({
        url: `/api/support/tickets/${ticketId}/close`,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as Ticket
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
      const response = await client.post({
        url: `/api/support/tickets/${ticketId}/reopen`,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as Ticket
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
      await client.delete({
        url: `/api/support/tickets/${ticketId}`,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
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
      const response = await client.get({
        url: `/api/support/tickets/${ticketId}/messages`,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as TicketMessage[]
    },
    enabled: !!ticketId,
  })
}

export function useCreateTicketMessage(ticketId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: { bodyMarkdown: string; isInternalNote?: boolean }) => {
      const response = await client.post({
        url: `/api/support/tickets/${ticketId}/messages`,
        body: payload,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as TicketMessage
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["support", "ticket", ticketId, "messages"] })
      queryClient.invalidateQueries({ queryKey: ["support", "ticket", ticketId] })
      queryClient.invalidateQueries({ queryKey: ["support", "tickets"] })
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
      await client.delete({
        url: `/api/support/tickets/${ticketId}/messages/${messageId}`,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
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

// ── Attachment Hooks ───────────────────────────────────────────────────

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
    },
    onError: (error) => {
      toast.error("Unable to upload image", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteAttachment(ticketId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (attachmentId: string) => {
      await client.delete({
        url: `/api/support/attachments/${attachmentId}`,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["support", "ticket", ticketId, "messages"] })
      toast.success("Attachment deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete attachment", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
