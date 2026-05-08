import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  type AdminGatewaySettings,
  type AdminGatewaySettingsUpdate,
  type DeviceGatewayResponse,
  type ExtensionGatewayResponse,
  gatewayLookupDevice,
  gatewayLookupExtension,
  gatewayLookupNumber,
  getAdminGatewaySettings,
  type NumberGatewayResponse,
  updateAdminGatewaySettings,
} from "@/lib/generated/api"

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

export type { AdminGatewaySettings, AdminGatewaySettingsUpdate }

export function useAdminGatewaySettings() {
  return useQuery({
    queryKey: ["admin", "gateway", "settings"],
    queryFn: async () => {
      const response = await getAdminGatewaySettings()
      return response.data as AdminGatewaySettings
    },
  })
}

export function useUpdateAdminGatewaySettings() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: AdminGatewaySettingsUpdate) => {
      const response = await updateAdminGatewaySettings({
        body: payload,
      })
      return response.data as AdminGatewaySettings
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
