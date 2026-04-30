import { useQuery } from "@tanstack/react-query"
import {
  gatewayLookupNumber,
  gatewayLookupExtension,
  gatewayLookupDevice,
  type NumberGatewayResponse,
  type ExtensionGatewayResponse,
  type DeviceGatewayResponse,
} from "@/lib/generated/api"

// ---------------------------------------------------------------------------
// Phone Number Lookup
// ---------------------------------------------------------------------------

export function useGatewayLookupNumber(phoneNumber: string) {
  return useQuery({
    queryKey: ["gateway", "number", phoneNumber],
    queryFn: async () => {
      const response = await gatewayLookupNumber({
        path: { phone_number: phoneNumber },
      })
      return response.data as NumberGatewayResponse
    },
    enabled: false,
  })
}

// ---------------------------------------------------------------------------
// Extension Lookup
// ---------------------------------------------------------------------------

export function useGatewayLookupExtension(extensionNumber: string) {
  return useQuery({
    queryKey: ["gateway", "extension", extensionNumber],
    queryFn: async () => {
      const response = await gatewayLookupExtension({
        path: { extension_number: extensionNumber },
      })
      return response.data as ExtensionGatewayResponse
    },
    enabled: false,
  })
}

// ---------------------------------------------------------------------------
// Device Lookup
// ---------------------------------------------------------------------------

export function useGatewayLookupDevice(macAddress: string) {
  return useQuery({
    queryKey: ["gateway", "device", macAddress],
    queryFn: async () => {
      const response = await gatewayLookupDevice({
        path: { mac_address: macAddress },
      })
      return response.data as DeviceGatewayResponse
    },
    enabled: false,
  })
}
