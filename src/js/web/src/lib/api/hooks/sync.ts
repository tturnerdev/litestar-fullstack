import { useMutation, useQueryClient } from "@tanstack/react-query"
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

const DOMAIN_QUERY_KEYS: Record<string, string[][]> = {
  extensions: [
    ["voice", "extensions"],
    ["voice", "extension"],
  ],
  "phone-numbers": [
    ["voice", "phone-numbers"],
    ["voice", "phone-number"],
  ],
  devices: [["devices"], ["device"]],
  "fax-numbers": [
    ["fax", "numbers"],
    ["fax", "number"],
  ],
}

export function useSyncEntity() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ domain, field, value }: SyncParams) => {
      const { data } = await client.get({
        url: `/api/sync/${domain}/${field}/${encodeURIComponent(value)}`,
        security: [{ scheme: "bearer", type: "http" }],
        throwOnError: true,
      })
      return data as SyncResponse
    },
    onSuccess: (_data, { domain }) => {
      const keys = DOMAIN_QUERY_KEYS[domain]
      if (keys) {
        for (const queryKey of keys) {
          queryClient.invalidateQueries({ queryKey })
        }
      }
      toast.success("Sync complete")
    },
    onError: (error) => {
      toast.error("Sync failed", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
