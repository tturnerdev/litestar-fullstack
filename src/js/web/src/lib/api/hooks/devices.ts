import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  createDevice,
  deleteDevice,
  type Device,
  type DeviceCreate,
  type DeviceLineAssignment,
  type DeviceUpdate,
  type ExtensionDeviceSummary,
  getDevice,
  listDevices,
  listExtensionDevices,
  type ListDevicesData,
  updateDevice,
} from "@/lib/generated/api"
import { client } from "@/lib/generated/api/client.gen"

// ---------------------------------------------------------------------------
// Helpers (for endpoints not yet in generated SDK)
// ---------------------------------------------------------------------------

function getAuthHeaders(): Record<string, string> {
  const token = typeof window !== "undefined" ? window.localStorage.getItem("access_token") : null
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function apiFetch<T>(url: string, options?: RequestInit): Promise<T> {
  const config = client.getConfig()
  const baseUrl = config.baseUrl ?? ""
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...getAuthHeaders(),
  }
  const response = await fetch(`${baseUrl}${url}`, {
    credentials: "include",
    ...options,
    headers: { ...headers, ...(options?.headers as Record<string, string>) },
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail ?? `Request failed (${response.status})`)
  }
  if (response.status === 204) return undefined as unknown as T
  return response.json()
}

async function apiFetchBlob(url: string): Promise<Blob> {
  const config = client.getConfig()
  const baseUrl = config.baseUrl ?? ""
  const response = await fetch(`${baseUrl}${url}`, {
    credentials: "include",
    headers: getAuthHeaders(),
  })
  if (!response.ok) {
    if (response.status === 504) throw new Error("Device timed out — is it reachable?")
    if (response.status === 401 || response.status === 403) throw new Error("Device rejected credentials")
    if (response.status === 502) throw new Error("Could not connect to device")
    throw new Error(`Screenshot failed (${response.status})`)
  }
  return response.blob()
}

// ---------------------------------------------------------------------------
// Device List
// ---------------------------------------------------------------------------

export interface UseDevicesOptions {
  page?: number
  pageSize?: number
  search?: string
  orderBy?: string
  sortOrder?: "asc" | "desc"
  refetchInterval?: number | false
}

export function useDevices(pageOrOptions: number | UseDevicesOptions = 1, pageSizeArg = 20) {
  const opts: UseDevicesOptions =
    typeof pageOrOptions === "number" ? { page: pageOrOptions, pageSize: pageSizeArg } : pageOrOptions
  const { page = 1, pageSize = 20, search, orderBy, sortOrder, refetchInterval } = opts

  return useQuery({
    queryKey: ["devices", page, pageSize, search, orderBy, sortOrder],
    queryFn: async () => {
      const query: ListDevicesData["query"] = {
        currentPage: page,
        pageSize,
      }
      if (search) {
        query.searchString = search
        query.searchIgnoreCase = true
      }
      if (orderBy) query.orderBy = orderBy
      if (sortOrder) query.sortOrder = sortOrder
      const response = await listDevices({ query })
      return response.data as { items: Device[]; total: number }
    },
    refetchInterval,
  })
}

// ---------------------------------------------------------------------------
// Device Detail
// ---------------------------------------------------------------------------

export function useDevice(deviceId: string) {
  return useQuery({
    queryKey: ["device", deviceId],
    queryFn: async () => {
      const response = await getDevice({ path: { device_id: deviceId } })
      return response.data as Device
    },
    enabled: !!deviceId,
  })
}

// ---------------------------------------------------------------------------
// Device Mutations
// ---------------------------------------------------------------------------

export function useCreateDevice() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: DeviceCreate) => {
      const response = await createDevice({ body: payload })
      return response.data as Device
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["devices"] })
      toast.success("Device created")
    },
    onError: (error) => {
      toast.error("Unable to create device", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUpdateDevice(deviceId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: DeviceUpdate) => {
      const response = await updateDevice({
        path: { device_id: deviceId },
        body: payload,
      })
      return response.data as Device
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["devices"] })
      queryClient.invalidateQueries({ queryKey: ["device", deviceId] })
      toast.success("Device updated")
    },
    onError: (error) => {
      toast.error("Unable to update device", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteDevice() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (deviceId: string) => {
      const response = await deleteDevice({ path: { device_id: deviceId } })
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["devices"] })
      toast.success("Device deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete device", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Device Actions (reboot, reprovision)
// ---------------------------------------------------------------------------

export function useRebootDevice(deviceId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => apiFetch<{ message: string }>(`/api/devices/${deviceId}/reboot`, { method: "POST" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["device", deviceId] })
      toast.success("Reboot command sent")
    },
    onError: (error) => {
      toast.error("Unable to reboot device", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useReprovisionDevice(deviceId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => apiFetch<{ message: string }>(`/api/devices/${deviceId}/reprovision`, { method: "POST" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["device", deviceId] })
      toast.success("Reprovisioning started")
    },
    onError: (error) => {
      toast.error("Unable to reprovision device", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Device Lines
// ---------------------------------------------------------------------------

export function useDeviceLines(deviceId: string) {
  return useQuery({
    queryKey: ["device", deviceId, "lines"],
    queryFn: () => apiFetch<{ items: DeviceLineAssignment[]; total: number }>(`/api/devices/${deviceId}/lines`),
    enabled: !!deviceId,
  })
}

export interface SetDeviceLinesPayload {
  lineNumber: number
  label: string
  lineType: string
  extensionId?: string | null
  isActive?: boolean
}

export function useSetDeviceLines(deviceId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (lines: SetDeviceLinesPayload[]) =>
      apiFetch<DeviceLineAssignment[]>(`/api/devices/${deviceId}/lines`, {
        method: "PUT",
        body: JSON.stringify(lines),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["device", deviceId] })
      queryClient.invalidateQueries({ queryKey: ["device", deviceId, "lines"] })
      toast.success("Line assignments saved")
    },
    onError: (error) => {
      toast.error("Unable to save line assignments", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Device Action (Action URI key press)
// ---------------------------------------------------------------------------

export function useDeviceAction(deviceId: string) {
  return useMutation({
    mutationFn: (key: string) =>
      apiFetch<{ deviceId: string; action: string; status: string; message: string }>(
        `/api/devices/${deviceId}/action?key=${encodeURIComponent(key)}`,
        { method: "POST" },
      ),
    onSuccess: (data) => {
      toast.success(data.message || "Action completed")
    },
    onError: (error) => {
      toast.error("Action failed", {
        description: error instanceof Error ? error.message : "Could not reach device",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Devices by Extension (server-side)
// ---------------------------------------------------------------------------

export function useDevicesByExtension(extensionId: string | undefined) {
  return useQuery({
    queryKey: ["devices", "by-extension", extensionId],
    queryFn: async () => {
      const response = await listExtensionDevices({ path: { ext_id: extensionId! } })
      return response.data as ExtensionDeviceSummary[]
    },
    enabled: !!extensionId,
  })
}

// ---------------------------------------------------------------------------
// Devices by Location (client-side filter)
// ---------------------------------------------------------------------------

export function useDevicesByLocation(locationId: string | undefined) {
  return useQuery({
    queryKey: ["devices", "by-location", locationId],
    queryFn: async () => {
      const query: ListDevicesData["query"] = { pageSize: 200 }
      const response = await listDevices({ query })
      const data = response.data as { items: Device[]; total: number }
      return (data.items ?? []).filter((d) => d.locationId === locationId)
    },
    enabled: !!locationId,
  })
}

// ---------------------------------------------------------------------------
// Devices by Team (client-side filter)
// ---------------------------------------------------------------------------

export function useDevicesByTeam(teamId: string | undefined) {
  return useQuery({
    queryKey: ["devices", "by-team", teamId],
    queryFn: async () => {
      const query: ListDevicesData["query"] = { pageSize: 200 }
      const response = await listDevices({ query })
      const data = response.data as { items: Device[]; total: number }
      return (data.items ?? []).filter((d) => d.teamId === teamId)
    },
    enabled: !!teamId,
  })
}

// ---------------------------------------------------------------------------
// Device Screenshot (LCD live view)
// ---------------------------------------------------------------------------

export function useDeviceScreenshot(deviceId: string, enabled: boolean) {
  return useQuery({
    queryKey: ["device", deviceId, "screenshot"],
    queryFn: () => apiFetchBlob(`/api/devices/${deviceId}/screenshot`),
    enabled: !!deviceId && enabled,
    refetchOnWindowFocus: false,
    staleTime: 0,
    retry: false,
  })
}
