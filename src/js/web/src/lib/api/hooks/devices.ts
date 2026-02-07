import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  createDevice,
  deleteDevice,
  type Device,
  type DeviceCreate,
  getDevice,
  listDevices,
  type ListDevicesData,
  updateDevice,
} from "@/lib/generated/api"

export function useDevices(page = 1, pageSize = 20) {
  return useQuery({
    queryKey: ["devices", page, pageSize],
    queryFn: async () => {
      const query = {
        currentPage: page,
        pageSize,
      } as unknown as ListDevicesData["query"]
      const response = await listDevices({ query })
      return response.data as { items: Device[]; total: number }
    },
  })
}

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
    mutationFn: async (payload: Record<string, unknown>) => {
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
