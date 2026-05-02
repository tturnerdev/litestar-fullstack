import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  type DeviceGatewayResponse,
  type ExtensionGatewayResponse,
  gatewayLookupDevice,
  gatewayLookupExtension,
  gatewayLookupNumber,
  type NumberGatewayResponse,
} from "@/lib/generated/api"
import { client } from "@/lib/generated/api/client.gen"

// ---------------------------------------------------------------------------
// Phone Number Lookup
// ---------------------------------------------------------------------------

export function useGatewayLookupNumber(phoneNumber: string, enabled = false) {
  return useQuery({
    queryKey: ["gateway", "number", phoneNumber],
    queryFn: async () => {
      const response = await gatewayLookupNumber({
        path: { phone_number: phoneNumber },
      })
      return response.data as NumberGatewayResponse
    },
    enabled: enabled && !!phoneNumber,
    staleTime: 5 * 60 * 1000,
  })
}

// ---------------------------------------------------------------------------
// Extension Lookup
// ---------------------------------------------------------------------------

export function useGatewayLookupExtension(extensionNumber: string, enabled = false) {
  return useQuery({
    queryKey: ["gateway", "extension", extensionNumber],
    queryFn: async () => {
      const response = await gatewayLookupExtension({
        path: { extension_number: extensionNumber },
      })
      return response.data as ExtensionGatewayResponse
    },
    enabled: enabled && !!extensionNumber,
    staleTime: 5 * 60 * 1000,
  })
}

// ---------------------------------------------------------------------------
// Device Lookup
// ---------------------------------------------------------------------------

export function useGatewayLookupDevice(macAddress: string, enabled = false) {
  return useQuery({
    queryKey: ["gateway", "device", macAddress],
    queryFn: async () => {
      const response = await gatewayLookupDevice({
        path: { mac_address: macAddress },
      })
      return response.data as DeviceGatewayResponse
    },
    enabled: enabled && !!macAddress,
    staleTime: 5 * 60 * 1000,
  })
}

// ---------------------------------------------------------------------------
// Admin Gateway Settings
// ---------------------------------------------------------------------------

export interface GatewaySettings {
  defaultTimeout: number
  defaultCacheTtl: number
}

export interface GatewaySettingsUpdate {
  defaultTimeout?: number
  defaultCacheTtl?: number
}

export function useAdminGatewaySettings() {
  return useQuery({
    queryKey: ["admin", "gateway", "settings"],
    queryFn: async () => {
      const response = await client.get({
        url: "/api/admin/gateway/settings",
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as GatewaySettings
    },
  })
}

export function useUpdateAdminGatewaySettings() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: GatewaySettingsUpdate) => {
      const response = await client.put({
        url: "/api/admin/gateway/settings",
        body: payload,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as GatewaySettings
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "gateway", "settings"] })
      toast.success("Gateway settings updated")
    },
    onError: (error) => {
      toast.error("Unable to update gateway settings", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
