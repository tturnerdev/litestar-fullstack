import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  confirmMfaSetup,
  disableMfa,
  initiateDisableMfaOAuth,
  initiateMfaSetup,
  profileOAuthLink,
  profileOAuthUnlink,
  regenerateMfaBackupCodes,
  verifyMfaChallenge,
} from "@/lib/generated/api"
import { getMfaStatusOptions, profileOAuthAccountsOptions, profileOAuthAccountsQueryKey } from "@/lib/generated/api/@tanstack/react-query.gen"

export function useMfaStatus() {
  return useQuery(getMfaStatusOptions())
}

export function useInitiateMfaSetup() {
  return useMutation({
    mutationFn: async () => {
      const { data } = await initiateMfaSetup({ throwOnError: true })
      return data
    },
    onError: (error) => {
      toast.error("Unable to set up MFA", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useConfirmMfaSetup() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (code: string) => {
      const { data } = await confirmMfaSetup({
        body: { code },
        throwOnError: true,
      })
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["getMfaStatus"] })
    },
    onError: (error) => {
      toast.error("Unable to confirm MFA setup", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDisableMfa() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (password: string) => {
      const { data } = await disableMfa({
        body: { password },
        throwOnError: true,
      })
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["getMfaStatus"] })
      toast.success("MFA disabled")
    },
    onError: (error) => {
      toast.error("Unable to disable MFA", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useInitiateDisableMfaOAuth() {
  return useMutation({
    mutationFn: async (provider: string) => {
      const { data } = await initiateDisableMfaOAuth({
        path: { provider },
        throwOnError: true,
      })
      return data
    },
    onError: (error) => {
      toast.error("Unable to disable MFA via OAuth", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useRegenerateBackupCodes() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (password: string) => {
      const { data } = await regenerateMfaBackupCodes({
        body: { password },
        throwOnError: true,
      })
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["getMfaStatus"] })
      toast.success("Backup codes regenerated")
    },
    onError: (error) => {
      toast.error("Unable to regenerate backup codes", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useVerifyMfaChallenge() {
  return useMutation({
    mutationFn: async (payload: { code?: string; recovery_code?: string }) => {
      const { data } = await verifyMfaChallenge({
        body: payload,
        throwOnError: true,
        // MFA challenge uses cookie-based auth (mfa_challenge cookie), not bearer token
        // Override security to prevent client from adding Authorization header
        security: [],
      })
      return data
    },
    onError: (error) => {
      toast.error("Unable to verify MFA code", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useOAuthAccounts() {
  return useQuery(profileOAuthAccountsOptions())
}

export function useStartOAuthLink() {
  return useMutation({
    mutationFn: async (payload: { provider: string; redirectUrl: string }) => {
      const { data } = await profileOAuthLink({
        path: { provider: payload.provider },
        query: { redirect_url: payload.redirectUrl },
        throwOnError: true,
      })
      return data
    },
    onError: (error) => {
      toast.error("Unable to link OAuth account", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUnlinkOAuthAccount() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (provider: string) => {
      const { data } = await profileOAuthUnlink({
        path: { provider },
        throwOnError: true,
      })
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: profileOAuthAccountsQueryKey(),
      })
    },
    onError: (error) => {
      toast.error("Unable to unlink OAuth account", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
