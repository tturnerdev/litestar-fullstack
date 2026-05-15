import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  deleteNotification as deleteNotificationApi,
  deleteReadNotifications,
  getNotificationPreferences,
  getUnreadNotificationCount,
  listNotifications,
  markAllNotificationsRead,
  markNotificationRead,
  type Notification,
  type NotificationPreference,
  type NotificationPreferenceUpdate,
  type UnreadCount,
  updateNotificationPreferences as updatePrefsApi,
} from "@/lib/generated/api"

export type NotificationItem = Notification
export type { NotificationPreference, UnreadCount }

export const notificationsQueryKey = (page = 1, pageSize = 20) => ["notifications", page, pageSize] as const
export const unreadCountQueryKey = () => ["notifications", "unread-count"] as const

export function useNotifications(
  page = 1,
  pageSize = 20,
  options?: {
    refetchInterval?: number | false
  },
) {
  return useQuery({
    queryKey: notificationsQueryKey(page, pageSize),
    queryFn: async () => {
      const response = await listNotifications({
        query: { currentPage: page, pageSize },
      })
      return response.data as { items: Notification[]; total: number }
    },
    ...(options?.refetchInterval !== undefined ? { refetchInterval: options.refetchInterval } : {}),
  })
}

export function useUnreadCount() {
  return useQuery({
    queryKey: unreadCountQueryKey(),
    queryFn: async () => {
      const response = await getUnreadNotificationCount()
      return response.data as UnreadCount
    },
    refetchInterval: 30_000,
  })
}

export function useMarkRead() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (notificationId: string) => {
      const response = await markNotificationRead({
        path: { notification_id: notificationId },
      })
      return response.data as Notification
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notifications"] })
    },
    onError: (error) => {
      toast.error("Unable to mark notification as read", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useMarkAllRead() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      const response = await markAllNotificationsRead()
      return response.data as UnreadCount
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
      await deleteNotificationApi({
        path: { notification_id: notificationId },
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notifications"] })
    },
  })
}

export function useDeleteAllRead() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      await deleteReadNotifications()
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

const PREFERENCES_QUERY_KEY = ["notificationPreferences"] as const

export function useNotificationPreferences() {
  return useQuery({
    queryKey: PREFERENCES_QUERY_KEY,
    queryFn: async () => {
      const response = await getNotificationPreferences()
      return response.data as NotificationPreference
    },
    staleTime: 5 * 60 * 1000,
  })
}

export function useUpdateNotificationPreferences() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (body: NotificationPreferenceUpdate) => {
      const response = await updatePrefsApi({ body })
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
      toast.error("Failed to update notification preferences", {
        description: _err instanceof Error ? _err.message : undefined,
      })
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: PREFERENCES_QUERY_KEY })
    },
  })
}
