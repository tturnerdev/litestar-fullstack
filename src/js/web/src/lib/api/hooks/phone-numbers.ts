import { useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { client } from "@/lib/generated/api/client.gen"

// Types matching the backend schema (camelCase per CamelizedBaseStruct)
export interface BulkImportRowPreview {
  rowNumber: number
  number: string
  friendlyName: string | null
  numberType: string
  capability: string
  status: string
  city: string | null
  state: string | null
  country: string
  provider: string | null
  isDuplicate: boolean
}

export interface BulkImportRowError {
  rowNumber: number
  errors: string[]
}

export interface BulkImportPhoneNumberPreview {
  validRows: BulkImportRowPreview[]
  errorRows: BulkImportRowError[]
  duplicateNumbers: string[]
  totalRows: number
  validCount: number
  errorCount: number
  duplicateCount: number
}

export interface BulkImportRowData {
  number: string
  friendlyName?: string | null
  numberType?: string
  capability?: string
  status?: string
  city?: string | null
  state?: string | null
  country?: string
  provider?: string | null
}

export interface BulkImportPhoneNumberRequest {
  rows: BulkImportRowData[]
  skipDuplicates?: boolean
}

export interface BulkImportPhoneNumberResult {
  createdCount: number
  skippedCount: number
  errorCount: number
  createdIds: string[]
  errors: string[]
}

export function usePhoneNumberBulkImportPreview() {
  return useMutation({
    mutationFn: async (file: File): Promise<BulkImportPhoneNumberPreview> => {
      const formData = new FormData()
      formData.append("data", file)

      const config = client.getConfig()
      const baseUrl = config.baseUrl || ""
      const token = window.localStorage.getItem("access_token")

      const response = await fetch(`${baseUrl}/api/admin/phone-numbers/bulk-import/preview`, {
        method: "POST",
        body: formData,
        headers: {
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => null)
        throw new Error(errorData?.detail || `Upload failed: ${response.statusText}`)
      }

      return response.json()
    },
    onError: (error) => {
      toast.error("CSV preview failed", {
        description: error instanceof Error ? error.message : "Unable to parse CSV file",
      })
    },
  })
}

export function usePhoneNumberBulkImportExecute() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (data: BulkImportPhoneNumberRequest): Promise<BulkImportPhoneNumberResult> => {
      const config = client.getConfig()
      const baseUrl = config.baseUrl || ""
      const token = window.localStorage.getItem("access_token")

      const response = await fetch(`${baseUrl}/api/admin/phone-numbers/bulk-import/execute`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(data),
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => null)
        throw new Error(errorData?.detail || `Import failed: ${response.statusText}`)
      }

      return response.json()
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["admin", "phone-numbers"] })
      queryClient.invalidateQueries({ queryKey: ["phone-numbers"] })
      toast.success(`Successfully imported ${data.createdCount} phone numbers`, {
        description: data.skippedCount > 0 ? `${data.skippedCount} duplicates skipped` : undefined,
      })
    },
    onError: (error) => {
      toast.error("Bulk import failed", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
