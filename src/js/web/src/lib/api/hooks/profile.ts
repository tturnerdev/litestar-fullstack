import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  accountPasswordUpdate,
  accountProfile,
  accountProfileUpdate,
  revokeAllSessions,
  revokeSession,
} from "@/lib/generated/api"
import {
  accountProfileQueryKey,
  getActiveSessionsOptions,
  getActiveSessionsQueryKey,
} from "@/lib/generated/api/@tanstack/react-query.gen"
import type { ProfileUpdate } from "@/lib/generated/api/types.gen"

export function useProfile() {
  return useQuery({
    queryKey: accountProfileQueryKey(),
    queryFn: async () => {
      const response = await accountProfile()
      return response.data
    },
  })
}

export function useUpdateProfile() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (body: ProfileUpdate) => {
      const response = await accountProfileUpdate({ body })
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: accountProfileQueryKey() })
      toast.success("Profile updated")
    },
    onError: (error: Error) => {
      toast.error("Failed to update profile", {
        description: error.message || "Please try again",
      })
    },
  })
}

export function useChangePassword() {
  return useMutation({
    mutationFn: async (body: { currentPassword: string; newPassword: string }) => {
      const response = await accountPasswordUpdate({ body })
      return response.data
    },
    onSuccess: () => {
      toast.success("Password changed successfully")
    },
    onError: (error: Error) => {
      toast.error("Failed to change password", {
        description: error.message || "Check your current password and try again",
      })
    },
  })
}

export function useActiveSessions() {
  return useQuery(getActiveSessionsOptions())
}

export function useRevokeSession() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (sessionId: string) => {
      const response = await revokeSession({
        path: { session_id: sessionId },
      })
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: getActiveSessionsQueryKey() })
      toast.success("Session revoked")
    },
    onError: (error: Error) => {
      toast.error("Failed to revoke session", {
        description: error.message || "Please try again",
      })
    },
  })
}

export function useRevokeAllSessions() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      const response = await revokeAllSessions()
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: getActiveSessionsQueryKey() })
      toast.success("All other sessions revoked")
    },
    onError: (error: Error) => {
      toast.error("Failed to revoke sessions", {
        description: error.message || "Please try again",
      })
    },
  })
}
