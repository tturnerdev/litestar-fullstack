import { useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  adminImportDevices,
  adminImportExtensions,
  adminPreviewDeviceImport,
  adminPreviewExtensionImport,
  type BulkImportPreview,
  type BulkImportResult,
} from "@/lib/generated/api"

// ---------------------------------------------------------------------------
// Device Import
// ---------------------------------------------------------------------------

export function usePreviewDeviceImport() {
  return useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData()
      formData.append("file", file)
      const response = await adminPreviewDeviceImport({
        body: formData as unknown as Record<string, unknown>,
      })
      return response.data as BulkImportPreview
    },
    onError: (error) => {
      toast.error("Unable to preview device import", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useImportDevices() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData()
      formData.append("file", file)
      const response = await adminImportDevices({
        body: formData as unknown as Record<string, unknown>,
      })
      return response.data as BulkImportResult
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["devices"] })
      queryClient.invalidateQueries({ queryKey: ["admin", "devices"] })
      toast.success("Device import complete", {
        description: `${data.created} created, ${data.updated} updated, ${data.skipped} skipped`,
      })
    },
    onError: (error) => {
      toast.error("Unable to import devices", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Extension Import
// ---------------------------------------------------------------------------

export function usePreviewExtensionImport() {
  return useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData()
      formData.append("file", file)
      const response = await adminPreviewExtensionImport({
        body: formData as unknown as Record<string, unknown>,
      })
      return response.data as BulkImportPreview
    },
    onError: (error) => {
      toast.error("Unable to preview extension import", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useImportExtensions() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData()
      formData.append("file", file)
      const response = await adminImportExtensions({
        body: formData as unknown as Record<string, unknown>,
      })
      return response.data as BulkImportResult
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["admin", "voice"] })
      toast.success("Extension import complete", {
        description: `${data.created} created, ${data.updated} updated, ${data.skipped} skipped`,
      })
    },
    onError: (error) => {
      toast.error("Unable to import extensions", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
