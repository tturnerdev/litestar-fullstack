import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { client } from "@/lib/generated/api/client.gen"

export interface NotificationItem {
  id: string
  userId: string
  title: string
  message: string
  category: string
  isRead: boolean
  actionUrl: string | null
  metadata: Record<string, unknown> | null
  createdAt: string
  updatedAt: string
}

interface NotificationListResponse {
  items: NotificationItem[]
  total: number
}

interface UnreadCountResponse {
  count: number
}

export const notificationsQueryKey = (page = 1, pageSize = 20) => ["notifications", page, pageSize] as const
export const unreadCountQueryKey = () => ["notifications", "unread-count"] as const

export function useNotifications(page = 1, pageSize = 20) {
  return useQuery({
    queryKey: notificationsQueryKey(page, pageSize),
    queryFn: async () => {
      const response = await client.get({
        url: "/api/notifications",
        query: {
          currentPage: page,
          pageSize,
        },
        security: [{ scheme: "bearer", type: "http" }],
      })
      return response.data as NotificationListResponse
    },
  })
}

export function useUnreadCount() {
  return useQuery({
    queryKey: unreadCountQueryKey(),
    queryFn: async () => {
      const response = await client.get({
        url: "/api/notifications/unread-count",
        security: [{ scheme: "bearer", type: "http" }],
      })
      return response.data as UnreadCountResponse
    },
    refetchInterval: 30_000,
  })
}

export function useMarkRead() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (notificationId: string) => {
      const response = await client.patch({
        url: "/api/notifications/{notification_id}/read",
        path: { notification_id: notificationId },
        security: [{ scheme: "bearer", type: "http" }],
      })
      return response.data as NotificationItem
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notifications"] })
    },
  })
}

export function useMarkAllRead() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      const response = await client.post({
        url: "/api/notifications/mark-all-read",
        security: [{ scheme: "bearer", type: "http" }],
      })
      return response.data as UnreadCountResponse
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notifications"] })
      toast.success("All notifications marked as read")
    },
    onError: (error) => {
      toast.error("Failed to mark notifications as read", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteNotification() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (notificationId: string) => {
      await client.delete({
        url: "/api/notifications/{notification_id}",
        path: { notification_id: notificationId },
        security: [{ scheme: "bearer", type: "http" }],
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notifications"] })
      toast.success("Notification deleted")
    },
    onError: (error) => {
      toast.error("Failed to delete notification", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
