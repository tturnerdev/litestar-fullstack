import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  createWebhook,
  deleteWebhook,
  getWebhook,
  listWebhooks,
  testWebhook,
  updateWebhook,
  type CreateWebhookData,
  type DeleteWebhookData,
  type GetWebhookData,
  type ListWebhooksData,
  type UpdateWebhookData,
  type WebhookCreate,
  type WebhookDetail,
  type WebhookList,
  type WebhookTestResult,
  type WebhookUpdate,
} from "@/lib/generated/api"

// ---------------------------------------------------------------------------
// List Webhooks
// ---------------------------------------------------------------------------

export function useWebhooks(page = 1, pageSize = 25, search?: string) {
  return useQuery({
    queryKey: ["webhooks", page, pageSize, search],
    queryFn: async () => {
      const query = {
        currentPage: page,
        pageSize,
        searchString: search,
        searchIgnoreCase: search ? true : undefined,
      } as unknown as ListWebhooksData["query"]
      const response = await listWebhooks({ query })
      return response.data as { items: WebhookList[]; total: number }
    },
  })
}

// ---------------------------------------------------------------------------
// Get Webhook Detail
// ---------------------------------------------------------------------------

export function useWebhook(webhookId: string) {
  return useQuery({
    queryKey: ["webhook", webhookId],
    queryFn: async () => {
      const response = await getWebhook({
        path: { webhook_id: webhookId },
      } as unknown as GetWebhookData)
      return response.data as WebhookDetail
    },
    enabled: !!webhookId,
  })
}

// ---------------------------------------------------------------------------
// Create Webhook
// ---------------------------------------------------------------------------

export function useCreateWebhook() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: WebhookCreate) => {
      const response = await createWebhook({
        body: payload,
      } as CreateWebhookData)
      return response.data as WebhookDetail
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["webhooks"] })
      toast.success("Webhook created")
    },
    onError: (error) => {
      toast.error("Unable to create webhook", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Update Webhook
// ---------------------------------------------------------------------------

export function useUpdateWebhook(webhookId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: WebhookUpdate) => {
      const response = await updateWebhook({
        path: { webhook_id: webhookId },
        body: payload,
      } as unknown as UpdateWebhookData)
      return response.data as WebhookDetail
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["webhooks"] })
      queryClient.invalidateQueries({ queryKey: ["webhook", webhookId] })
      toast.success("Webhook updated")
    },
    onError: (error) => {
      toast.error("Unable to update webhook", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Delete Webhook
// ---------------------------------------------------------------------------

export function useDeleteWebhook() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (webhookId: string) => {
      const response = await deleteWebhook({
        path: { webhook_id: webhookId },
      } as unknown as DeleteWebhookData)
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["webhooks"] })
      toast.success("Webhook deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete webhook", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Test Webhook
// ---------------------------------------------------------------------------

export function useTestWebhook() {
  return useMutation({
    mutationFn: async (webhookId: string) => {
      const response = await testWebhook({
        path: { webhook_id: webhookId },
      } as unknown as { path: { webhook_id: string } })
      return response.data as WebhookTestResult
    },
    onSuccess: (data) => {
      if (data?.success) {
        toast.success("Webhook test successful", {
          description: `Status ${data.statusCode} in ${data.responseTimeMs}ms`,
        })
      } else {
        toast.error("Webhook test failed", {
          description: data?.error ?? "Unknown error",
        })
      }
    },
    onError: (error) => {
      toast.error("Unable to test webhook", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
