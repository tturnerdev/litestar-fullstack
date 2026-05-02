import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  type AdminListDeviceTemplatesData,
  adminCreateDeviceTemplate,
  adminDeleteDeviceTemplate,
  adminGetDeviceTemplate,
  adminListDeviceTemplates,
  adminUpdateDeviceTemplate,
  type DeviceTemplateCreate,
  type DeviceTemplateDetail,
  type DeviceTemplateList,
  type DeviceTemplateLookup,
  type DeviceTemplateUpdate,
  type LookupDeviceTemplateData,
  lookupDeviceTemplate,
} from "@/lib/generated/api"

// ---------------------------------------------------------------------------
// Admin: List Device Templates
// ---------------------------------------------------------------------------

export function useAdminDeviceTemplates(page = 1, pageSize = 25, search?: string) {
  return useQuery({
    queryKey: ["admin", "device-templates", page, pageSize, search],
    queryFn: async () => {
      const query = {
        currentPage: page,
        pageSize,
        searchString: search,
        searchIgnoreCase: search ? true : undefined,
      } as unknown as AdminListDeviceTemplatesData["query"]
      const response = await adminListDeviceTemplates({ query })
      return response.data as { items: DeviceTemplateList[]; total: number }
    },
  })
}

// ---------------------------------------------------------------------------
// Admin: Get Device Template Detail
// ---------------------------------------------------------------------------

export function useAdminDeviceTemplate(templateId: string) {
  return useQuery({
    queryKey: ["admin", "device-template", templateId],
    queryFn: async () => {
      const response = await adminGetDeviceTemplate({
        path: { template_id: templateId },
      })
      return response.data as DeviceTemplateDetail
    },
    enabled: !!templateId,
  })
}

// ---------------------------------------------------------------------------
// Admin: Create Device Template
// ---------------------------------------------------------------------------

export function useCreateDeviceTemplate() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: DeviceTemplateCreate) => {
      const response = await adminCreateDeviceTemplate({ body: payload })
      return response.data as DeviceTemplateDetail
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "device-templates"] })
      toast.success("Device template created")
    },
    onError: (error) => {
      toast.error("Unable to create device template", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Admin: Update Device Template
// ---------------------------------------------------------------------------

export function useUpdateDeviceTemplate(templateId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: DeviceTemplateUpdate) => {
      const response = await adminUpdateDeviceTemplate({
        path: { template_id: templateId },
        body: payload,
      })
      return response.data as DeviceTemplateDetail
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "device-templates"] })
      queryClient.invalidateQueries({ queryKey: ["admin", "device-template", templateId] })
      toast.success("Device template updated")
    },
    onError: (error) => {
      toast.error("Unable to update device template", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Admin: Delete Device Template
// ---------------------------------------------------------------------------

export function useDeleteDeviceTemplate() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (templateId: string) => {
      const response = await adminDeleteDeviceTemplate({
        path: { template_id: templateId },
      })
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "device-templates"] })
      toast.success("Device template deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete device template", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Lookup: Get template by manufacturer + model (non-admin)
// ---------------------------------------------------------------------------

export function useDeviceTemplateLookup(manufacturer: string | null | undefined, model: string | null | undefined, enabled = true) {
  return useQuery({
    queryKey: ["device-template-lookup", manufacturer, model],
    queryFn: async () => {
      const query: LookupDeviceTemplateData["query"] = {
        manufacturer: manufacturer as string,
        model: model as string,
      }
      const response = await lookupDeviceTemplate({ query })
      return response.data as DeviceTemplateLookup
    },
    enabled: enabled && !!manufacturer && !!model,
    retry: false,
  })
}
