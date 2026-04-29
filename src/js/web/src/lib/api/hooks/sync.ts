import { useMutation } from "@tanstack/react-query"
import { toast } from "sonner"
import { client } from "@/lib/generated/api/client.gen"

interface SyncParams {
  domain: string
  field: string
  value: string
}

interface SyncResponse {
  synced: boolean
  domain: string
  field: string
  value: string
  entity: Record<string, unknown>
  syncedAt: string
}

export function useSyncEntity() {
  return useMutation({
    mutationFn: async ({ domain, field, value }: SyncParams) => {
      const { data } = await client.get({
        url: `/api/sync/${domain}/${field}/${encodeURIComponent(value)}`,
        security: [{ scheme: "bearer", type: "http" }],
        throwOnError: true,
      })
      return data as SyncResponse
    },
    onSuccess: () => {
      toast.success("Synced successfully")
    },
    onError: (error) => {
      toast.error("Sync failed", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
