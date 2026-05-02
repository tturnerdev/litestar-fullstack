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

export function useDeleteAllRead() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      await client.delete({
        url: "/api/notifications/read",
        security: [{ scheme: "bearer", type: "http" }],
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notifications"] })
      toast.success("All read notifications deleted")
    },
    onError: (error) => {
      toast.error("Failed to delete read notifications", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// --- Notification Preferences ---

export interface NotificationPreference {
  id: string
  userId: string
  emailEnabled: boolean
  categories: Record<string, boolean>
}

interface NotificationPreferenceUpdate {
  emailEnabled?: boolean
  categories?: Record<string, boolean>
}

const PREFERENCES_QUERY_KEY = ["notificationPreferences"] as const

export function useNotificationPreferences() {
  return useQuery({
    queryKey: PREFERENCES_QUERY_KEY,
    queryFn: async () => {
      const response = await client.get({
        security: [{ scheme: "bearer", type: "http" }],
        url: "/api/notifications/preferences",
      })
      return response.data as NotificationPreference
    },
  })
}

export function useUpdateNotificationPreferences() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (body: NotificationPreferenceUpdate) => {
      const response = await client.patch({
        security: [{ scheme: "bearer", type: "http" }],
        url: "/api/notifications/preferences",
        body,
      })
      return response.data as NotificationPreference
    },
    onMutate: async (newData) => {
      await queryClient.cancelQueries({ queryKey: PREFERENCES_QUERY_KEY })
      const previous = queryClient.getQueryData<NotificationPreference>(PREFERENCES_QUERY_KEY)
      if (previous) {
        queryClient.setQueryData<NotificationPreference>(PREFERENCES_QUERY_KEY, {
          ...previous,
          ...(newData.emailEnabled !== undefined && { emailEnabled: newData.emailEnabled }),
          ...(newData.categories && {
            categories: { ...previous.categories, ...newData.categories },
          }),
        })
      }
      return { previous }
    },
    onSuccess: () => {
      toast.success("Notification preferences updated")
    },
    onError: (_err, _newData, context) => {
      if (context?.previous) {
        queryClient.setQueryData(PREFERENCES_QUERY_KEY, context.previous)
      }
      toast.error("Failed to update notification preferences")
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: PREFERENCES_QUERY_KEY })
    },
  })
}
